package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	wsGUID                = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxWSFrameSize        = 125 // Clients only send RFC 6455 control frames (<= 125 bytes)
	defaultMaxWSPerKey    = 8   // Max concurrent WebSocket connections per API key / principal
	defaultMaxWSTotal     = 128 // Max total concurrent WebSocket connections across the server
	defaultWSPingInterval = 25 * time.Second
	defaultWSPongWait     = 35 * time.Second
	defaultPort           = "8080"
	daemonTCPAddr         = "127.0.0.1:7583"
	configDir             = "/home/.local/share/signal-cli"
	minRootKeyLength      = 16
	maxAuthBodyBytes      = 4 * 1024        // 4 KB max body for login & key management
	maxRequestBodyBytes   = 64 * 1024       // 64 KB max body for send & reactions
	maxProfileBodyBytes   = 5 * 1024 * 1024 // 5 MB max body for profile update (including base64/multipart avatar)
	maxAvatarBytes        = 3 * 1024 * 1024 // 3 MB max decoded avatar image size
	maxAvatarDimension    = 1024            // Max avatar width/height in pixels (caps decoded buffer at ~4-8 MB)
)

var (
	appVersion         = "dev"
	errWSLimitExceeded = errors.New("websocket connection limit exceeded")
)

func effectiveVersion() string {
	if v := strings.TrimSpace(appVersion); v != "" && v != "dev" {
		return v
	}
	if envV := strings.TrimSpace(os.Getenv("APP_VERSION")); envV != "" {
		return envV
	}
	return "dev"
}

// Valid key permissions
const (
	PermSend    = "send"
	PermReceive = "receive"
	PermAdmin   = "admin"
)

var (
	e164Regex     = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	uuidRegex     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	groupIDRegex  = regexp.MustCompile(`^(group\.[A-Za-z0-9+/=_.-]{8,128}|[A-Za-z0-9+/=_-]{16,128})$`)
	usernameRegex = regexp.MustCompile(`^(u:)?[A-Za-z0-9_]{1,32}(\.[0-9]{2,9})?$`)
	keyIDRegex    = regexp.MustCompile(`^key_[0-9a-fA-F]{8,32}$`)
)

func isValidAccountIdentifier(val string) bool {
	val = strings.TrimSpace(val)
	if val == "" || strings.HasPrefix(val, "-") {
		return false
	}
	return e164Regex.MatchString(val) || uuidRegex.MatchString(val)
}

func isValidRecipientIdentifier(val string) bool {
	val = strings.TrimSpace(val)
	if val == "" || strings.HasPrefix(val, "-") {
		return false
	}
	return e164Regex.MatchString(val) || uuidRegex.MatchString(val) || groupIDRegex.MatchString(val) || usernameRegex.MatchString(val)
}

func isGroupRecipient(val string) bool {
	val = strings.TrimSpace(val)
	if val == "" || strings.HasPrefix(val, "-") {
		return false
	}
	if strings.HasPrefix(val, "group.") {
		return groupIDRegex.MatchString(val)
	}
	if e164Regex.MatchString(val) || uuidRegex.MatchString(val) {
		return false
	}
	if usernameRegex.MatchString(val) {
		// Signal usernames have a ".digits" discriminator, "u:" prefix, or are < 22 chars without base64 symbols
		if strings.Contains(val, ".") || strings.HasPrefix(val, "u:") || len(val) < 22 {
			return false
		}
	}
	return groupIDRegex.MatchString(val)
}

func normalizeGroupID(val string) string {
	return strings.TrimPrefix(strings.TrimSpace(val), "group.")
}

func isValidProfileName(val string, required bool) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return !required
	}
	if len(val) > 64 || strings.HasPrefix(val, "-") {
		return false
	}
	for _, r := range val {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func buildUpdateProfileParams(account, givenName, familyName, avatarPath string) map[string]interface{} {
	params := map[string]interface{}{
		"account":   strings.TrimSpace(account),
		"givenName": strings.TrimSpace(givenName),
	}
	if fn := strings.TrimSpace(familyName); fn != "" {
		params["familyName"] = fn
	}
	if ap := strings.TrimSpace(avatarPath); ap != "" {
		params["avatar"] = ap
	}
	return params
}

// sanitizeAvatarBytes fully decodes a PNG, JPEG, or GIF image (bounding dimensions first
// to prevent decompression bombs) and re-encodes it as a clean, metadata-free PNG image.
func sanitizeAvatarBytes(data []byte) ([]byte, string, error) {
	if len(data) == 0 {
		return nil, "", errors.New("avatar image data is empty")
	}
	if len(data) > maxAvatarBytes {
		return nil, "", fmt.Errorf("avatar image exceeds maximum size of %d bytes", maxAvatarBytes)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, "", errors.New("invalid or unsupported avatar image (allowed: valid PNG, JPEG, or GIF)")
	}
	switch format {
	case "png", "jpeg", "gif":
	default:
		return nil, "", fmt.Errorf("unsupported avatar image format %q (allowed: PNG, JPEG, GIF)", format)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxAvatarDimension || cfg.Height > maxAvatarDimension {
		return nil, "", fmt.Errorf("avatar dimensions %dx%d exceed maximum allowed %dx%d", cfg.Width, cfg.Height, maxAvatarDimension, maxAvatarDimension)
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", errors.New("corrupt or malformed avatar image payload")
	}

	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, "", errors.New("failed to re-encode avatar image")
	}
	return out.Bytes(), ".png", nil
}

func decodeAvatarData(raw string) ([]byte, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, "", nil
	}
	if strings.HasPrefix(trimmed, "data:") {
		commaIdx := strings.IndexByte(trimmed, ',')
		if commaIdx < 0 {
			return nil, "", errors.New("invalid avatar data URL")
		}
		meta := strings.ToLower(trimmed[:commaIdx])
		if !strings.HasSuffix(meta, ";base64") {
			return nil, "", errors.New("avatar data URL must be base64-encoded")
		}
		trimmed = strings.TrimSpace(trimmed[commaIdx+1:])
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, "", errors.New("invalid base64 avatar payload")
		}
	}
	return sanitizeAvatarBytes(decoded)
}

// -----------------------------------------------------------------------------
// Persistent API Key Store (Stores SHA-256 hashes only; independent random IDs)
// -----------------------------------------------------------------------------

type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Key         string     `json:"key,omitempty"`          // Returned once on creation; NEVER persisted to disk
	KeyHash     string     `json:"key_hash,omitempty"`     // Hex-encoded SHA-256 of the secret key
	Prefix      string     `json:"prefix"`                 // Display prefix (e.g. "sig_8a3f...d4")
	Accounts    []string   `json:"accounts"`               // Allowed account identifiers (or "*" for all)
	Permissions []string   `json:"permissions"`            // Allowed permissions: "send", "receive", "admin"
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"` // Updated when the key authenticates a request
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`   // Optional key expiration timestamp
}

func (k APIKey) HasPermission(perm string) bool {
	for _, p := range k.Permissions {
		if p == perm || p == PermAdmin || p == "*" {
			return true
		}
	}
	return false
}

func (k APIKey) AllowsAccount(account string) bool {
	if account == "" {
		return false
	}
	for _, a := range k.Accounts {
		if a == account || a == "*" {
			return true
		}
	}
	return false
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

type KeyStore struct {
	filePath string
	keys     map[string]APIKey // ID -> APIKey (with KeyHash, empty Key)
	mu       sync.RWMutex
	saveMu   sync.Mutex
	lastUsed sync.Map // keyID (string) -> UnixNano (int64)
	dirty    atomic.Bool
}

func newKeyStore(filePath string) (*KeyStore, error) {
	ks := &KeyStore{
		filePath: filePath,
		keys:     make(map[string]APIKey),
	}
	if err := ks.load(); err != nil {
		return nil, err
	}
	go ks.flushLoop(time.Minute)
	return ks, nil
}

func (ks *KeyStore) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := ks.FlushLastUsed(); err != nil {
			log.Printf("[keystore] Background last_used_at flush error: %v", err)
		}
	}
}

func (ks *KeyStore) effectiveLastUsed(id string, stored *time.Time) *time.Time {
	var best time.Time
	if stored != nil {
		best = stored.UTC()
	}
	if val, ok := ks.lastUsed.Load(id); ok {
		if ns, ok := val.(int64); ok {
			t := time.Unix(0, ns).UTC()
			if best.IsZero() || t.After(best) {
				best = t
			}
		}
	}
	if best.IsZero() {
		return nil
	}
	return &best
}

// FlushLastUsed writes pending last_used_at updates to disk without holding ks.mu during file I/O.
func (ks *KeyStore) FlushLastUsed() error {
	if !ks.dirty.CompareAndSwap(true, false) {
		return nil
	}
	ks.saveMu.Lock()
	defer ks.saveMu.Unlock()

	ks.mu.RLock()
	list := ks.snapshotLocked()
	ks.mu.RUnlock()

	if err := ks.writeListToDisk(list); err != nil {
		ks.dirty.Store(true)
		return err
	}
	return nil
}

func (ks *KeyStore) load() error {
	ks.saveMu.Lock()
	defer ks.saveMu.Unlock()
	ks.mu.Lock()
	defer ks.mu.Unlock()

	data, err := os.ReadFile(ks.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("error reading %s: %w", ks.filePath, err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("error parsing %s: file is empty", ks.filePath)
	}

	var stored []APIKey
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("error parsing %s: %w", ks.filePath, err)
	}

	migrated := false
	for _, k := range stored {
		if k.ID == "" {
			return fmt.Errorf("error parsing %s: key entry missing id", ks.filePath)
		}
		// Migrate legacy plaintext key if present, never keeping plaintext in memory
		if k.KeyHash == "" && k.Key != "" {
			k.KeyHash = hashSecret(k.Key)
			migrated = true
		}
		if k.Key != "" {
			k.Key = ""
			migrated = true
		}
		if k.KeyHash == "" {
			return fmt.Errorf("error parsing %s: key %s missing key_hash", ks.filePath, k.ID)
		}
		ks.keys[k.ID] = k
	}
	if migrated {
		if err := ks.save(); err != nil {
			return fmt.Errorf("error persisting migrated keys to %s: %w", ks.filePath, err)
		}
		log.Printf("[keystore] Migrated legacy plaintext key(s) to SHA-256 hashes on disk.")
	}
	log.Printf("[keystore] Loaded %d client API key(s) from persistent store.", len(ks.keys))
	return nil
}

// snapshotLocked builds the slice of keys to persist. Caller must hold ks.mu (RLock or Lock).
func (ks *KeyStore) snapshotLocked() []APIKey {
	list := make([]APIKey, 0, len(ks.keys))
	for _, k := range ks.keys {
		persisted := k
		persisted.Key = "" // Never persist plaintext secret
		persisted.LastUsedAt = ks.effectiveLastUsed(k.ID, k.LastUsedAt)
		list = append(list, persisted)
	}
	return list
}

// save atomically writes the key store via a temporary file and rename.
// Caller must hold ks.saveMu and ks.mu (lock order: saveMu -> mu).
func (ks *KeyStore) save() error {
	list := ks.snapshotLocked()
	return ks.writeListToDisk(list)
}

func (ks *KeyStore) writeListToDisk(list []APIKey) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(ks.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	} else {
		dir = "."
	}

	tmpFile, err := os.CreateTemp(dir, ".api_keys-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmpFile.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	if err := os.Rename(tmpName, ks.filePath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func normalizeAccounts(accounts []string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, a := range accounts {
		trimmed := strings.TrimSpace(a)
		if trimmed == "" {
			continue
		}
		if trimmed != "*" && !isValidAccountIdentifier(trimmed) {
			return nil, fmt.Errorf("invalid account identifier %q (must be E.164 phone number, UUID, or '*')", trimmed)
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one allowed account is required")
	}
	return out, nil
}

func normalizePermissions(perms []string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, p := range perms {
		norm := strings.ToLower(strings.TrimSpace(p))
		if norm == "" {
			continue
		}
		switch norm {
		case PermSend, PermReceive, PermAdmin:
		default:
			return nil, fmt.Errorf("invalid permission %q (must be send, receive, or admin)", norm)
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one permission (send, receive, or admin) is required")
	}
	return out, nil
}

func (ks *KeyStore) CreateKey(name string, accounts []string, permissions []string) (APIKey, error) {
	return ks.CreateKeyWithExpiry(name, accounts, permissions, nil)
}

func (ks *KeyStore) CreateKeyWithExpiry(name string, accounts []string, permissions []string, expiresAt *time.Time) (APIKey, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return APIKey{}, errors.New("key name is required (max 128 chars)")
	}

	normAccounts, err := normalizeAccounts(accounts)
	if err != nil {
		return APIKey{}, err
	}

	normPerms, err := normalizePermissions(permissions)
	if err != nil {
		return APIKey{}, err
	}

	// Generate key ID independently from the secret key material
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return APIKey{}, err
	}
	secretBytes := make([]byte, 24)
	if _, err := rand.Read(secretBytes); err != nil {
		return APIKey{}, err
	}

	id := "key_" + hex.EncodeToString(idBytes)
	secret := "sig_" + hex.EncodeToString(secretBytes)
	prefix := "sig_" + hex.EncodeToString(secretBytes[:2]) + "..."
	keyHash := hashSecret(secret)
	now := time.Now().UTC()

	var expCopy *time.Time
	if expiresAt != nil {
		utcExp := expiresAt.UTC()
		if !utcExp.After(now) {
			return APIKey{}, errors.New("expires_at must be in the future")
		}
		expCopy = &utcExp
	}

	storedEntry := APIKey{
		ID:          id,
		Name:        name,
		KeyHash:     keyHash,
		Prefix:      prefix,
		Accounts:    normAccounts,
		Permissions: normPerms,
		CreatedAt:   now,
		ExpiresAt:   expCopy,
	}

	// Always acquire saveMu before mu to match FlushLastUsed lock ordering
	ks.saveMu.Lock()
	defer ks.saveMu.Unlock()
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.keys[id] = storedEntry
	if err := ks.save(); err != nil {
		delete(ks.keys, id)
		return APIKey{}, fmt.Errorf("failed to persist key: %w", err)
	}

	// Return full key string once to the caller; omit KeyHash in response
	returned := storedEntry
	returned.Key = secret
	returned.KeyHash = ""
	return returned, nil
}

func (ks *KeyStore) RevokeKey(id string) (bool, error) {
	// Always acquire saveMu before mu to match FlushLastUsed lock ordering
	ks.saveMu.Lock()
	defer ks.saveMu.Unlock()
	ks.mu.Lock()
	defer ks.mu.Unlock()

	entry, ok := ks.keys[id]
	if !ok {
		return false, nil
	}

	delete(ks.keys, id)
	if err := ks.save(); err != nil {
		// Restore in-memory state if atomic persistence failed
		ks.keys[id] = entry
		return false, fmt.Errorf("failed to persist key revocation: %w", err)
	}
	ks.lastUsed.Delete(id)
	return true, nil
}

func (ks *KeyStore) ListKeys() []APIKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var list []APIKey
	for _, k := range ks.keys {
		accounts := k.Accounts
		if accounts == nil {
			accounts = []string{}
		}
		perms := k.Permissions
		if perms == nil {
			perms = []string{}
		}
		lastUsedCopy := ks.effectiveLastUsed(k.ID, k.LastUsedAt)
		var expCopy *time.Time
		if k.ExpiresAt != nil {
			t := *k.ExpiresAt
			expCopy = &t
		}
		list = append(list, APIKey{
			ID:          k.ID,
			Name:        k.Name,
			Prefix:      k.Prefix,
			Accounts:    accounts,
			Permissions: perms,
			CreatedAt:   k.CreatedAt,
			LastUsedAt:  lastUsedCopy,
			ExpiresAt:   expCopy,
		})
	}
	if list == nil {
		list = []APIKey{}
	}
	return list
}

func constantTimeEquals(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// IsKeyActive reports whether a key ID still exists in the store and has not expired.
func (ks *KeyStore) IsKeyActive(id string) bool {
	if id == "" {
		return false
	}
	now := time.Now().UTC()
	ks.mu.RLock()
	k, ok := ks.keys[id]
	ks.mu.RUnlock()
	if !ok {
		return false
	}
	if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		return false
	}
	return true
}

func (ks *KeyStore) LookupKey(token string) (APIKey, bool) {
	if token == "" {
		return APIKey{}, false
	}
	candidateHash := hashSecret(token)
	now := time.Now().UTC()

	ks.mu.RLock()
	var matched APIKey
	var found bool
	for _, k := range ks.keys {
		if subtle.ConstantTimeCompare([]byte(candidateHash), []byte(k.KeyHash)) == 1 {
			matched = k
			found = true
		}
	}
	ks.mu.RUnlock()

	if !found {
		return APIKey{}, false
	}
	if matched.ExpiresAt != nil && !now.Before(*matched.ExpiresAt) {
		return APIKey{}, false
	}

	ks.lastUsed.Store(matched.ID, now.UnixNano())
	ks.dirty.Store(true)
	matched.LastUsedAt = &now
	return matched, true
}

func (ks *KeyStore) ValidateKey(token string, rootKey string) bool {
	if token == "" {
		return false
	}
	if rootKey != "" && constantTimeEquals(token, rootKey) {
		return true
	}
	_, ok := ks.LookupKey(token)
	return ok
}

// -----------------------------------------------------------------------------
// Admin Session Store (Enforces 3-min hard TTL + 2-min server-side idle timeout)
// -----------------------------------------------------------------------------

const (
	defaultSessionTTL  = 3 * time.Minute // 3 minutes hard timeout
	defaultIdleTimeout = 2 * time.Minute // 2 minutes server-side inactivity lock
)

type sessionEntry struct {
	expiresAt    time.Time
	lastActivity time.Time
}

type SessionStore struct {
	sessions    map[string]sessionEntry
	mu          sync.Mutex
	ttl         time.Duration
	idleTimeout time.Duration
	onEnd       []func(token string)
}

func newSessionStore(ttl time.Duration) *SessionStore {
	idle := (ttl * 2) / 3
	if ttl == defaultSessionTTL {
		idle = defaultIdleTimeout
	}
	if idle <= 0 {
		idle = ttl
	}
	ss := &SessionStore{
		sessions:    make(map[string]sessionEntry),
		ttl:         ttl,
		idleTimeout: idle,
	}

	sweepInterval := ttl / 2
	if sweepInterval < 15*time.Millisecond {
		sweepInterval = 15 * time.Millisecond
	} else if sweepInterval > 5*time.Second {
		sweepInterval = 5 * time.Second
	}

	// Background sweeper for expired or idle admin sessions
	go func() {
		ticker := time.NewTicker(sweepInterval)
		for range ticker.C {
			var expired []string
			var callbacks []func(string)
			ss.mu.Lock()
			now := time.Now()
			for tok, entry := range ss.sessions {
				if now.After(entry.expiresAt) || now.Sub(entry.lastActivity) > ss.idleTimeout {
					delete(ss.sessions, tok)
					expired = append(expired, tok)
				}
			}
			if len(expired) > 0 && len(ss.onEnd) > 0 {
				callbacks = append(callbacks, ss.onEnd...)
			}
			ss.mu.Unlock()

			for _, tok := range expired {
				for _, fn := range callbacks {
					fn(tok)
				}
			}
		}
	}()

	return ss
}

func (ss *SessionStore) OnSessionEnd(fn func(token string)) {
	if ss == nil || fn == nil {
		return
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.onEnd = append(ss.onEnd, fn)
}

func (ss *SessionStore) CreateSession() (string, int) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	token := "adm_sess_" + hex.EncodeToString(raw)
	now := time.Now()
	ss.sessions[token] = sessionEntry{
		expiresAt:    now.Add(ss.ttl),
		lastActivity: now,
	}
	secs := int(ss.ttl.Seconds())
	if secs == 0 && ss.ttl > 0 {
		secs = 1
	}
	return token, secs
}

func (ss *SessionStore) ValidateSession(token string) bool {
	if token == "" {
		return false
	}
	ss.mu.Lock()

	now := time.Now()
	var matchedKey string
	var matchedEntry sessionEntry
	for k, entry := range ss.sessions {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k)) == 1 {
			matchedKey = k
			matchedEntry = entry
		}
	}
	if matchedKey == "" {
		ss.mu.Unlock()
		return false
	}
	if now.After(matchedEntry.expiresAt) || now.Sub(matchedEntry.lastActivity) > ss.idleTimeout {
		delete(ss.sessions, matchedKey)
		callbacks := append([]func(string){}, ss.onEnd...)
		ss.mu.Unlock()
		for _, fn := range callbacks {
			fn(matchedKey)
		}
		return false
	}
	matchedEntry.lastActivity = now
	ss.sessions[matchedKey] = matchedEntry
	ss.mu.Unlock()
	return true
}

// IsSessionActive checks whether a session is still unexpired and non-idle without extending lastActivity.
func (ss *SessionStore) IsSessionActive(token string) bool {
	if token == "" {
		return false
	}
	ss.mu.Lock()

	now := time.Now()
	var matchedKey string
	var matchedEntry sessionEntry
	for k, entry := range ss.sessions {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k)) == 1 {
			matchedKey = k
			matchedEntry = entry
		}
	}
	if matchedKey == "" {
		ss.mu.Unlock()
		return false
	}
	if now.After(matchedEntry.expiresAt) || now.Sub(matchedEntry.lastActivity) > ss.idleTimeout {
		delete(ss.sessions, matchedKey)
		callbacks := append([]func(string){}, ss.onEnd...)
		ss.mu.Unlock()
		for _, fn := range callbacks {
			fn(matchedKey)
		}
		return false
	}
	ss.mu.Unlock()
	return true
}

func (ss *SessionStore) RevokeSession(token string) {
	if token == "" {
		return
	}
	var revoked []string
	ss.mu.Lock()
	for k := range ss.sessions {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k)) == 1 {
			delete(ss.sessions, k)
			revoked = append(revoked, k)
		}
	}
	callbacks := append([]func(string){}, ss.onEnd...)
	ss.mu.Unlock()

	if len(revoked) == 0 {
		revoked = []string{token}
	}
	for _, tok := range revoked {
		for _, fn := range callbacks {
			fn(tok)
		}
	}
}

// -----------------------------------------------------------------------------
// Rate Limiters (Login Lockout & Per-Account Send Rate Limiting)
// -----------------------------------------------------------------------------

type RateLimiter struct {
	mu          sync.Mutex
	window      time.Duration
	maxRequests int
	baseDelay   time.Duration
	maxDelay    time.Duration
	events      map[string][]time.Time
	nextAllowed map[string]time.Time
}

func newRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		window:      window,
		maxRequests: maxRequests,
		baseDelay:   50 * time.Millisecond,
		maxDelay:    2 * time.Second,
		events:      make(map[string][]time.Time),
		nextAllowed: make(map[string]time.Time),
	}

	sweepInterval := window / 2
	if sweepInterval < 25*time.Millisecond {
		sweepInterval = 25 * time.Millisecond
	} else if sweepInterval > 30*time.Second {
		sweepInterval = 30 * time.Second
	}

	// Background sweeper to evict expired rate-limit buckets so the map never grows unboundedly
	go func() {
		ticker := time.NewTicker(sweepInterval)
		for range ticker.C {
			rl.Sweep(time.Now())
		}
	}()

	return rl
}

// Sweep removes expired event timestamps and deletes empty/inactive buckets.
func (rl *RateLimiter) Sweep(now time.Time) {
	if rl == nil {
		return
	}
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	for bucket, history := range rl.events {
		valid := history[:0]
		for _, t := range history {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.events, bucket)
			if next, ok := rl.nextAllowed[bucket]; !ok || !next.After(now) {
				delete(rl.nextAllowed, bucket)
			}
		} else {
			rl.events[bucket] = valid
		}
	}
	for bucket, next := range rl.nextAllowed {
		if !next.After(now) && len(rl.events[bucket]) == 0 {
			delete(rl.nextAllowed, bucket)
		}
	}
}

func (rl *RateLimiter) Allow(bucket string) bool {
	if rl == nil || rl.maxRequests <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	history := rl.events[bucket]
	valid := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.maxRequests {
		rl.events[bucket] = valid
		return false
	}
	rl.events[bucket] = append(valid, now)
	return true
}

// IsLocked reports whether the bucket has reached maxRequests within the active window.
func (rl *RateLimiter) IsLocked(bucket string) bool {
	if rl == nil || rl.maxRequests <= 0 {
		return false
	}
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	history := rl.events[bucket]
	valid := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) == 0 {
		delete(rl.events, bucket)
		return false
	}
	rl.events[bucket] = valid
	return len(valid) >= rl.maxRequests
}

// ThrottleFailure atomically records a failed login attempt, computes a growing exponential
// backoff delay, and reports whether the failure count has reached maxRequests.
func (rl *RateLimiter) ThrottleFailure(bucket string) (time.Duration, bool) {
	if rl == nil {
		return 0, false
	}
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	history := rl.events[bucket]
	valid := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if rl.maxRequests <= 0 || len(valid) < rl.maxRequests {
		valid = append(valid, now)
	} else if len(valid) > rl.maxRequests {
		valid = valid[len(valid)-rl.maxRequests:]
	}
	rl.events[bucket] = valid
	failures := len(valid)

	base := rl.baseDelay
	if base <= 0 {
		base = 50 * time.Millisecond
	}
	maxD := rl.maxDelay
	if maxD <= 0 {
		maxD = 2 * time.Second
	}

	shift := failures - 1
	if shift < 0 {
		shift = 0
	} else if shift > 6 {
		shift = 6
	}
	step := base * time.Duration(1<<shift)
	if step > maxD {
		step = maxD
	}

	start := now
	if next, ok := rl.nextAllowed[bucket]; ok && next.After(now) {
		start = next
	}
	scheduled := start.Add(step)
	rl.nextAllowed[bucket] = scheduled

	wait := scheduled.Sub(now)
	if wait > maxD {
		wait = maxD
	}
	rateLimited := rl.maxRequests > 0 && failures >= rl.maxRequests
	return wait, rateLimited
}

func (rl *RateLimiter) Reset(bucket string) {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.events, bucket)
	delete(rl.nextAllowed, bucket)
}

func (rl *RateLimiter) BucketCount() int {
	if rl == nil {
		return 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.events)
}

// -----------------------------------------------------------------------------
// WebSocket Client & Hub (RFC 6455 compliant, pure Go standard library)
// -----------------------------------------------------------------------------

type WSClient struct {
	conn         net.Conn
	account      string
	keyID        string
	sessionToken string
	hub          *WSHub
	closed       atomic.Bool
	mu           sync.Mutex
}

func wsOwnerBucket(keyID, sessionToken string) string {
	if keyID != "" {
		return "key:" + keyID
	}
	if sessionToken != "" {
		return "sess:" + sessionToken
	}
	return "default"
}

func (c *WSClient) ownerBucket() string {
	return wsOwnerBucket(c.keyID, c.sessionToken)
}

func (c *WSClient) close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	_ = c.conn.Close()

	if c.hub != nil {
		c.hub.mu.Lock()
		delete(c.hub.clients, c)
		c.hub.mu.Unlock()
	}
}

func (c *WSClient) writeFrame(opcode byte, payload []byte) error {
	if c.closed.Load() {
		return errors.New("client connection closed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return errors.New("client connection closed")
	}

	length := len(payload)
	header := []byte{0x80 | (opcode & 0x0F)}

	if length <= 125 {
		header = append(header, byte(length))
	} else if length <= 65535 {
		header = append(header, 126)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(length))
		header = append(header, lenBytes...)
	} else {
		header = append(header, 127)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(length))
		header = append(header, lenBytes...)
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.conn.Write(append(header, payload...)); err != nil {
		return err
	}
	return nil
}

type HistoryEntry struct {
	Data       []byte
	ReceivedAt time.Time
}

type WSHub struct {
	clients          map[*WSClient]bool
	mu               sync.RWMutex
	history          map[string][]HistoryEntry // account -> last 50 messages
	maxPerKey        int
	maxTotal         int
	pingInterval     time.Duration
	pongWait         time.Duration
	sessionValidator func(token string) bool
	keyValidator     func(keyID string) bool
}

func newWSHub() *WSHub {
	return &WSHub{
		clients:      make(map[*WSClient]bool),
		history:      make(map[string][]HistoryEntry),
		maxPerKey:    defaultMaxWSPerKey,
		maxTotal:     defaultMaxWSTotal,
		pingInterval: defaultWSPingInterval,
		pongWait:     defaultWSPongWait,
	}
}

func (h *WSHub) effectiveMaxPerKey() int {
	if h != nil && h.maxPerKey > 0 {
		return h.maxPerKey
	}
	return defaultMaxWSPerKey
}

func (h *WSHub) effectiveMaxTotal() int {
	if h != nil && h.maxTotal > 0 {
		return h.maxTotal
	}
	return defaultMaxWSTotal
}

func (h *WSHub) effectivePingInterval() time.Duration {
	if h != nil && h.pingInterval > 0 {
		return h.pingInterval
	}
	return defaultWSPingInterval
}

func (h *WSHub) effectivePongWait() time.Duration {
	if h != nil && h.pongWait > 0 {
		return h.pongWait
	}
	if h != nil && h.pingInterval > 0 {
		return h.pingInterval * 2
	}
	return defaultWSPongWait
}

func (h *WSHub) canAccept(keyID, sessionToken string) error {
	if h == nil {
		return nil
	}
	bucket := wsOwnerBucket(keyID, sessionToken)
	maxTotal := h.effectiveMaxTotal()
	maxPerKey := h.effectiveMaxPerKey()

	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.clients) >= maxTotal {
		return errWSLimitExceeded
	}
	count := 0
	for c := range h.clients {
		if c.ownerBucket() == bucket {
			count++
			if count >= maxPerKey {
				return errWSLimitExceeded
			}
		}
	}
	return nil
}

func (h *WSHub) tryRegister(c *WSClient) error {
	if h == nil {
		return nil
	}
	bucket := c.ownerBucket()
	maxTotal := h.effectiveMaxTotal()
	maxPerKey := h.effectiveMaxPerKey()

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.clients) >= maxTotal {
		return errWSLimitExceeded
	}
	count := 0
	for existing := range h.clients {
		if existing.ownerBucket() == bucket {
			count++
			if count >= maxPerKey {
				return errWSLimitExceeded
			}
		}
	}
	h.clients[c] = true
	return nil
}

// extractMessageAccount parses the target Signal account from a JSON-RPC receive notification or envelope.
func extractMessageAccount(raw []byte) string {
	var msg struct {
		Account string `json:"account"`
		Params  struct {
			Account  string `json:"account"`
			Envelope struct {
				Account string `json:"account"`
			} `json:"envelope"`
		} `json:"params"`
		Envelope struct {
			Account string `json:"account"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return ""
	}
	if msg.Params.Account != "" {
		return msg.Params.Account
	}
	if msg.Account != "" {
		return msg.Account
	}
	if msg.Params.Envelope.Account != "" {
		return msg.Params.Envelope.Account
	}
	if msg.Envelope.Account != "" {
		return msg.Envelope.Account
	}
	return ""
}

func (h *WSHub) Publish(account string, message []byte) {
	now := time.Now().UTC()
	if account == "" {
		account = extractMessageAccount(message)
	}
	if account == "" {
		return
	}

	msgCopy := append([]byte(nil), message...)

	h.mu.Lock()
	h.history[account] = append(h.history[account], HistoryEntry{
		Data:       msgCopy,
		ReceivedAt: now,
	})
	if len(h.history[account]) > 50 {
		h.history[account] = h.history[account][len(h.history[account])-50:]
	}

	var targets []*WSClient
	for client := range h.clients {
		if client.account == account || client.account == "*" {
			targets = append(targets, client)
		}
	}
	sessValidator := h.sessionValidator
	keyValidator := h.keyValidator
	h.mu.Unlock()

	for _, client := range targets {
		if client.sessionToken != "" && sessValidator != nil && !sessValidator(client.sessionToken) {
			_ = client.writeFrame(0x08, []byte{0x03, 0xF0}) // 1008 Policy Violation
			client.close()
			continue
		}
		if strings.HasPrefix(client.keyID, "key_") && keyValidator != nil && !keyValidator(client.keyID) {
			_ = client.writeFrame(0x08, []byte{0x03, 0xF0}) // 1008 Policy Violation
			client.close()
			continue
		}
		go func(c *WSClient, msg []byte) {
			if err := c.writeFrame(0x01, msg); err != nil {
				c.close()
			}
		}(client, msgCopy)
	}
}

func (h *WSHub) GetHistory(account string, since time.Time) []json.RawMessage {
	if account == "" {
		return []json.RawMessage{}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()

	entries := h.history[account]
	items := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		if !since.IsZero() && entry.ReceivedAt.Before(since) {
			continue
		}
		items = append(items, json.RawMessage(entry.Data))
	}
	return items
}

func (h *WSHub) DisconnectKey(keyID string) {
	if keyID == "" {
		return
	}
	h.mu.RLock()
	var toClose []*WSClient
	for client := range h.clients {
		if client.keyID == keyID {
			toClose = append(toClose, client)
		}
	}
	h.mu.RUnlock()

	for _, c := range toClose {
		c.close()
	}
}

func (h *WSHub) DisconnectSession(sessionToken string) {
	if sessionToken == "" {
		return
	}
	h.mu.RLock()
	var toClose []*WSClient
	for client := range h.clients {
		if client.sessionToken != "" && constantTimeEquals(client.sessionToken, sessionToken) {
			toClose = append(toClose, client)
		}
	}
	h.mu.RUnlock()

	for _, c := range toClose {
		_ = c.writeFrame(0x08, []byte{0x03, 0xF0}) // 1008 Policy Violation
		c.close()
	}
}

func (h *WSHub) ClientCount() int {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *WSHub) run() {
	ticker := time.NewTicker(h.effectivePingInterval())
	defer ticker.Stop()

	for range ticker.C {
		h.mu.RLock()
		clients := make([]*WSClient, 0, len(h.clients))
		for client := range h.clients {
			clients = append(clients, client)
		}
		sessValidator := h.sessionValidator
		keyValidator := h.keyValidator
		h.mu.RUnlock()

		for _, client := range clients {
			if client.sessionToken != "" && sessValidator != nil && !sessValidator(client.sessionToken) {
				_ = client.writeFrame(0x08, []byte{0x03, 0xF0}) // 1008 Policy Violation
				client.close()
				continue
			}
			if strings.HasPrefix(client.keyID, "key_") && keyValidator != nil && !keyValidator(client.keyID) {
				_ = client.writeFrame(0x08, []byte{0x03, 0xF0}) // 1008 Policy Violation
				client.close()
				continue
			}
			go func(c *WSClient) {
				if err := c.writeFrame(0x09, []byte{}); err != nil {
					c.close()
				}
			}(client)
		}
	}
}

func upgradeWebSocket(w http.ResponseWriter, r *http.Request, account string, keyID string, sessionToken string, hub *WSHub) (*WSClient, error) {
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		return nil, errors.New("expected websocket upgrade")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}

	if err := hub.canAccept(keyID, sessionToken); err != nil {
		return nil, err
	}

	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("server does not support hijacking")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	client := &WSClient{
		conn:         conn,
		account:      account,
		keyID:        keyID,
		sessionToken: sessionToken,
		hub:          hub,
	}

	if err := hub.tryRegister(client); err != nil {
		_ = conn.Close()
		return nil, err
	}

	response := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n",
		acceptKey,
	)

	if _, err := bufrw.WriteString(response); err != nil {
		client.close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		client.close()
		return nil, err
	}

	// Enforce initial read deadline; only extended when the client sends a Pong (or Ping) control frame
	_ = conn.SetReadDeadline(time.Now().Add(hub.effectivePongWait()))

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[ws] Recovered from panic in WebSocket reader: %v", rec)
			}
			client.close()
		}()
		reader := bufio.NewReader(conn)
		for {
			b1, err := reader.ReadByte()
			if err != nil {
				return
			}
			opcode := b1 & 0x0F
			if opcode == 0x08 {
				return
			}

			b2, err := reader.ReadByte()
			if err != nil {
				return
			}
			isMasked := (b2 & 0x80) != 0
			if !isMasked {
				// RFC 6455 Section 5.1: client frames MUST be masked
				_ = client.writeFrame(0x08, []byte{0x03, 0xEA}) // 1002 Protocol Error
				return
			}

			frameLen := uint64(b2 & 0x7F)
			if frameLen == 126 {
				var l uint16
				if err := binary.Read(reader, binary.BigEndian, &l); err != nil {
					return
				}
				frameLen = uint64(l)
			} else if frameLen == 127 {
				var l uint64
				if err := binary.Read(reader, binary.BigEndian, &l); err != nil {
					return
				}
				frameLen = l
			}

			if frameLen > maxWSFrameSize {
				// 1009 Message Too Big
				_ = client.writeFrame(0x08, []byte{0x03, 0xF1})
				return
			}
			length := int(frameLen)

			maskKey := make([]byte, 4)
			if _, err := io.ReadFull(reader, maskKey); err != nil {
				return
			}

			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}

			for i := 0; i < length; i++ {
				payload[i] ^= maskKey[i%4]
			}

			switch opcode {
			case 0x09: // Ping -> extend read deadline and reply with Pong
				_ = conn.SetReadDeadline(time.Now().Add(hub.effectivePongWait()))
				_ = client.writeFrame(0x0A, payload)
			case 0x0A: // Pong -> extend read deadline
				_ = conn.SetReadDeadline(time.Now().Add(hub.effectivePongWait()))
			}
		}
	}()

	return client, nil
}

// -----------------------------------------------------------------------------
// Signal-CLI JSON-RPC Client & Subprocess Manager
// -----------------------------------------------------------------------------

type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type SignalDaemon struct {
	cmd         *exec.Cmd
	conn        net.Conn
	mu          sync.Mutex
	stopped     bool
	stopCh      chan struct{}
	reqID       int64
	pendingReqs map[int64]chan *JSONRPCResponse
	hub         *WSHub
}

func newSignalDaemon(hub *WSHub) *SignalDaemon {
	return &SignalDaemon{
		stopCh:      make(chan struct{}),
		pendingReqs: make(map[int64]chan *JSONRPCResponse),
		hub:         hub,
	}
}

func (s *SignalDaemon) stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped {
		s.stopped = true
		if s.stopCh != nil {
			close(s.stopCh)
		}
	}
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

func buildDaemonCommand() *exec.Cmd {
	cmd := exec.Command(
		"signal-cli",
		"--config", configDir,
		"daemon",
		"--tcp", daemonTCPAddr,
		"--no-receive-stdout",
	)
	// Never forward signal-cli stdout/stderr directly to container logs by default,
	// so message content, sender metadata, or phone numbers cannot leak into logs.
	cmd.Stdout = io.Discard
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LOG_DAEMON_STDERR")), "true") {
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stderr = io.Discard
	}
	return cmd
}

func (s *SignalDaemon) start() {
	go func() {
		for {
			s.mu.Lock()
			if s.stopped {
				s.mu.Unlock()
				return
			}
			log.Println("[signal-daemon] Starting signal-cli daemon process...")
			cmd := buildDaemonCommand()
			s.cmd = cmd

			if err := cmd.Start(); err != nil {
				s.mu.Unlock()
				log.Printf("[signal-daemon] Failed to start signal-cli: %v. Retrying in 5s...", err)
				select {
				case <-s.stopCh:
					return
				case <-time.After(5 * time.Second):
					continue
				}
			}
			s.mu.Unlock()

			select {
			case <-s.stopCh:
				return
			case <-time.After(2 * time.Second):
			}
			s.connectSocket()

			waitErr := cmd.Wait()
			s.mu.Lock()
			stopped := s.stopped
			s.mu.Unlock()
			if stopped {
				return
			}
			if waitErr != nil {
				log.Printf("[signal-daemon] signal-cli daemon exited with error: %v. Restarting in 3s...", waitErr)
			} else {
				log.Println("[signal-daemon] signal-cli daemon exited cleanly. Restarting in 3s...")
			}
			select {
			case <-s.stopCh:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
}

func (s *SignalDaemon) connectSocket() {
	var conn net.Conn
	var err error

	for i := 0; i < 20; i++ {
		conn, err = net.Dial("tcp", daemonTCPAddr)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		log.Printf("[signal-daemon] Warning: Could not connect to daemon socket: %v", err)
		return
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	log.Println("[signal-daemon] Connected to signal-cli JSON-RPC socket!")

	go s.readLoop(conn)
}

func (s *SignalDaemon) readLoop(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			log.Printf("[signal-daemon] Socket read error: %v", err)
			return
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var resp JSONRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}

		if resp.Method == "receive" {
			s.hub.Publish("", line)
			continue
		}

		if resp.ID > 0 {
			s.mu.Lock()
			ch, ok := s.pendingReqs[resp.ID]
			if ok {
				delete(s.pendingReqs, resp.ID)
				ch <- &resp
			}
			s.mu.Unlock()
		}
	}
}

func (s *SignalDaemon) call(method string, params interface{}) (json.RawMessage, error) {
	if s == nil {
		return nil, errors.New("daemon not initialized")
	}
	id := atomic.AddInt64(&s.reqID, 1)
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      id,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	reqBytes = append(reqBytes, '\n')

	ch := make(chan *JSONRPCResponse, 1)

	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return nil, errors.New("daemon socket not connected")
	}
	s.pendingReqs[id] = ch
	s.mu.Unlock()

	if _, err := conn.Write(reqBytes); err != nil {
		s.mu.Lock()
		delete(s.pendingReqs, id)
		s.mu.Unlock()
		return nil, err
	}

	select {
	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	case <-time.After(15 * time.Second):
		s.mu.Lock()
		delete(s.pendingReqs, id)
		s.mu.Unlock()
		return nil, errors.New("rpc call timed out")
	}
}

func readRecoveryKey(account string, r io.Reader) (string, error) {
	if f, ok := r.(*os.File); ok {
		if info, err := f.Stat(); err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
			fmt.Fprintf(os.Stderr, "Enter Recovery Key for account %q: ", account)
			line, err := bufio.NewReader(f).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return "", fmt.Errorf("failed to read recovery key from stdin: %w", err)
			}
			key := strings.TrimSpace(line)
			if key == "" {
				return "", errors.New("recovery key read from stdin cannot be empty")
			}
			return key, nil
		}
	}
	rawKey, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", fmt.Errorf("failed to read recovery key from stdin: %w", err)
	}
	key := strings.TrimSpace(string(rawKey))
	if key == "" {
		return "", errors.New("recovery key read from stdin cannot be empty")
	}
	return key, nil
}

func buildRegisterCLIFlags(account, recoveryKey string, extraFlags []string) ([]string, error) {
	account = strings.TrimSpace(account)
	if account == "" || strings.HasPrefix(account, "-") {
		return nil, errors.New("valid account identifier is required")
	}
	recoveryKey = strings.TrimSpace(recoveryKey)
	if recoveryKey == "" {
		return nil, errors.New("recovery key cannot be empty")
	}
	args := []string{"--config", configDir, "-a", account, "register", "--recovery-key", recoveryKey}
	for i := 0; i < len(extraFlags); i++ {
		arg := extraFlags[i]
		switch {
		case arg == "--reregister", arg == "--voice":
			args = append(args, arg)
		case arg == "--captcha":
			if i+1 >= len(extraFlags) {
				return nil, errors.New("--captcha requires a value")
			}
			i++
			args = append(args, "--captcha", extraFlags[i])
		case strings.HasPrefix(arg, "--captcha="):
			args = append(args, arg)
		default:
			return nil, fmt.Errorf("unsupported flag %q for register-recovery", arg)
		}
	}
	return args, nil
}

// buildRegisterRPCRequest reads a recovery key from r (stdin) and builds a signal-cli JSON-RPC
// "register" request so the recovery key never appears in process arguments (argv / ps).
func buildRegisterRPCRequest(account string, r io.Reader, extraFlags []string) ([]byte, error) {
	account = strings.TrimSpace(account)
	if account == "" || strings.HasPrefix(account, "-") {
		return nil, errors.New("valid account identifier is required")
	}
	if r == nil {
		return nil, errors.New("stdin reader is required")
	}

	recoveryKey, err := readRecoveryKey(account, r)
	if err != nil {
		return nil, err
	}
	return buildRegisterRPCRequestFromKey(account, recoveryKey, extraFlags)
}

func buildRegisterRPCRequestFromKey(account, recoveryKey string, extraFlags []string) ([]byte, error) {
	params := map[string]interface{}{
		"account":     account,
		"recoveryKey": recoveryKey,
	}

	for i := 0; i < len(extraFlags); i++ {
		arg := extraFlags[i]
		switch {
		case arg == "--reregister":
			params["reregister"] = true
		case arg == "--voice":
			params["voice"] = true
		case arg == "--captcha":
			if i+1 >= len(extraFlags) {
				return nil, errors.New("--captcha requires a value")
			}
			i++
			params["captcha"] = extraFlags[i]
		case strings.HasPrefix(arg, "--captcha="):
			params["captcha"] = strings.TrimPrefix(arg, "--captcha=")
		default:
			return nil, fmt.Errorf("unsupported flag %q for register-recovery", arg)
		}
	}

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "register",
		Params:  params,
		ID:      1,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func parseRegisterRPCResponse(r io.Reader) error {
	if r == nil {
		return errors.New("empty signal-cli rpc response reader")
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}
		if resp.ID == 1 {
			if resp.Error != nil {
				return fmt.Errorf("signal-cli rpc error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading signal-cli rpc response: %w", err)
	}
	return errors.New("no matching JSON-RPC response received from signal-cli")
}

// runRegisterRecovery sends the JSON-RPC register request over the local daemon TCP socket
// (or via `signal-cli jsonRpc` stdin if the daemon is not reachable), falling back to the direct
// `signal-cli register --recovery-key` CLI when the account does not yet exist in accounts.json.
func runRegisterRecovery(account string, r io.Reader, extraFlags []string) error {
	account = strings.TrimSpace(account)
	if account == "" || strings.HasPrefix(account, "-") {
		return errors.New("valid account identifier is required")
	}
	if r == nil {
		return errors.New("stdin reader is required")
	}

	recoveryKey, err := readRecoveryKey(account, r)
	if err != nil {
		return err
	}
	reqBytes, err := buildRegisterRPCRequestFromKey(account, recoveryKey, extraFlags)
	if err != nil {
		return err
	}

	if conn, dialErr := net.DialTimeout("tcp", daemonTCPAddr, 2*time.Second); dialErr == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(reqBytes); err == nil {
			rpcErr := parseRegisterRPCResponse(conn)
			if rpcErr == nil {
				return nil
			}
			if !strings.Contains(rpcErr.Error(), "Failed to load the given account") &&
				strings.HasPrefix(rpcErr.Error(), "signal-cli rpc error") {
				return rpcErr
			}
		}
	}

	cliArgs, err := buildRegisterCLIFlags(account, recoveryKey, extraFlags)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "signal-cli", cliArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("signal-cli register failed: %s", msg)
		}
		return fmt.Errorf("signal-cli register failed: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Server Application & HTTP Handlers
// -----------------------------------------------------------------------------

type contextKey string

const principalContextKey contextKey = "auth_principal"

type AuthPrincipal struct {
	IsRoot       bool
	KeyID        string
	SessionToken string
	Accounts     []string
	Permissions  []string
	CreatedAt    time.Time
}

func (p *AuthPrincipal) HasPermission(perm string) bool {
	if p == nil {
		return false
	}
	if p.IsRoot {
		return true
	}
	for _, kPerm := range p.Permissions {
		if kPerm == perm || kPerm == PermAdmin || kPerm == "*" {
			return true
		}
	}
	return false
}

func (p *AuthPrincipal) AllowsAccount(account string) bool {
	if p == nil || account == "" {
		return false
	}
	if p.IsRoot {
		return true
	}
	for _, acc := range p.Accounts {
		if acc == account || acc == "*" {
			return true
		}
	}
	return false
}

func getPrincipal(r *http.Request) *AuthPrincipal {
	if val := r.Context().Value(principalContextKey); val != nil {
		if p, ok := val.(*AuthPrincipal); ok {
			return p
		}
	}
	return nil
}

type Server struct {
	daemon               *SignalDaemon
	hub                  *WSHub
	keyStore             *KeyStore
	sessionStore         *SessionStore
	apiKeyMgmt           string // Root administration key (used at /api/auth/login)
	allowUnauthenticated bool
	allowedHosts         map[string]bool
	allowedOrigins       map[string]bool
	trustedProxyHeader   string       // Optional header from reverse proxy (e.g. "X-Forwarded-For" or "X-Real-IP")
	trustedProxies       []*net.IPNet // Explicitly configured trusted reverse proxy CIDRs (default: none)
	profileUpdater       func(ctx context.Context, account, givenName, familyName, avatarPath string) ([]byte, error)
	loginLimiter         *RateLimiter
	sendLimiter          *RateLimiter
}

func parseTrustedProxies(raw string) []*net.IPNet {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var nets []*net.IPNet
	for _, item := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if !strings.Contains(trimmed, "/") {
			if ip := net.ParseIP(trimmed); ip != nil {
				if ip.To4() != nil {
					trimmed += "/32"
				} else {
					trimmed += "/128"
				}
			}
		}
		if _, ipNet, err := net.ParseCIDR(trimmed); err == nil {
			nets = append(nets, ipNet)
		}
	}
	return nets
}

func (s *Server) isTrustedProxyIP(ipStr string) bool {
	if len(s.trustedProxies) == 0 {
		return false
	}
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(ipStr), "[]"))
	if ip == nil {
		return false
	}
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func peerIPFromRequest(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return strings.Trim(host, "[]")
	}
	if r.RemoteAddr != "" {
		return strings.Trim(r.RemoteAddr, "[]")
	}
	return "local"
}

func firstHeaderToken(val string) string {
	if val == "" {
		return ""
	}
	parts := strings.Split(val, ",")
	return strings.TrimSpace(parts[0])
}

func (s *Server) realClientIP(r *http.Request) string {
	peer := peerIPFromRequest(r)
	headerName := strings.TrimSpace(s.trustedProxyHeader)
	if headerName != "" && s.isTrustedProxyIP(peer) {
		raw := strings.TrimSpace(r.Header.Get(headerName))
		if raw != "" {
			parts := strings.Split(raw, ",")
			// Walk rightmost-first to select the first non-trusted-proxy IP (or leftmost valid IP)
			for i := len(parts) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(parts[i])
				if host, _, err := net.SplitHostPort(candidate); err == nil && host != "" {
					candidate = host
				}
				candidate = strings.Trim(candidate, "[]")
				if ip := net.ParseIP(candidate); ip != nil {
					if i == 0 || !s.isTrustedProxyIP(candidate) {
						return ip.String()
					}
				}
			}
		}
	}
	return peer
}

func defaultAllowedHosts(extra string) map[string]bool {
	hosts := map[string]bool{
		"localhost": true,
		"127.0.0.1": true,
		"::1":       true,
	}
	for _, h := range strings.Split(extra, ",") {
		trimmed := strings.ToLower(strings.TrimSpace(h))
		if trimmed != "" {
			if splitHost, _, err := net.SplitHostPort(trimmed); err == nil {
				trimmed = strings.Trim(splitHost, "[]")
			} else {
				trimmed = strings.Trim(trimmed, "[]")
			}
			hosts[trimmed] = true
		}
	}
	return hosts
}

func normalizeScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http", "ws":
		return "http"
	case "https", "wss":
		return "https"
	default:
		return ""
	}
}

func canonicalHostPort(hostPort string, scheme string) string {
	scheme = normalizeScheme(scheme)
	if scheme == "" {
		scheme = "http"
	}
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return ""
	}
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		h = strings.ToLower(strings.Trim(h, "[]"))
		p = strings.TrimSpace(p)
		if h == "" || p == "" {
			return ""
		}
		return net.JoinHostPort(h, p)
	}
	h := strings.ToLower(strings.Trim(hostPort, "[]"))
	if h == "" {
		return ""
	}
	defaultPort := "80"
	if scheme == "https" {
		defaultPort = "443"
	}
	return net.JoinHostPort(h, defaultPort)
}

func normalizeOrigin(rawOrigin string) (scheme string, hostPort string, rawHost string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(rawOrigin))
	if err != nil || u.Host == "" {
		return "", "", "", false
	}
	scheme = normalizeScheme(u.Scheme)
	if scheme == "" {
		return "", "", "", false
	}
	hostPort = canonicalHostPort(u.Host, scheme)
	if hostPort == "" {
		return "", "", "", false
	}
	return scheme, hostPort, u.Host, true
}

func parseAllowedOrigins(extra string) map[string]bool {
	origins := make(map[string]bool)
	for _, o := range strings.Split(extra, ",") {
		trimmed := strings.TrimSpace(o)
		if trimmed == "" {
			continue
		}
		if scheme, hostPort, _, ok := normalizeOrigin(trimmed); ok {
			origins[scheme+"://"+hostPort] = true
		}
		origins[strings.ToLower(trimmed)] = true
	}
	return origins
}

func normalizeHost(hostPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return strings.ToLower(strings.Trim(h, "[]"))
	}
	if strings.HasPrefix(hostPort, "[") && strings.HasSuffix(hostPort, "]") {
		return strings.ToLower(strings.Trim(hostPort, "[]"))
	}
	return strings.ToLower(hostPort)
}

func (s *Server) isAllowedHost(hostHeader string) bool {
	h := normalizeHost(hostHeader)
	if h == "" {
		return false
	}
	allowed := s.allowedHosts
	if len(allowed) == 0 {
		allowed = defaultAllowedHosts("")
	}
	return allowed[h]
}

func (s *Server) effectiveRequestOrigin(r *http.Request) (scheme string, hostPort string) {
	scheme = "http"
	if r.TLS != nil {
		scheme = "https"
	}
	peer := peerIPFromRequest(r)
	if s.isTrustedProxyIP(peer) {
		if xfp := firstHeaderToken(r.Header.Get("X-Forwarded-Proto")); xfp != "" {
			if norm := normalizeScheme(xfp); norm != "" {
				scheme = norm
			}
		}
	}
	reqHost := r.Host
	if s.isTrustedProxyIP(peer) {
		if xfh := firstHeaderToken(r.Header.Get("X-Forwarded-Host")); xfh != "" && s.isAllowedHost(xfh) {
			reqHost = xfh
		}
	}
	return scheme, canonicalHostPort(reqHost, scheme)
}

func (s *Server) isAllowedOrigin(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if strings.EqualFold(origin, "null") {
		return false
	}
	origScheme, origHostPort, origRawHost, ok := normalizeOrigin(origin)
	if !ok {
		return false
	}
	if len(s.allowedOrigins) > 0 && (s.allowedOrigins[origScheme+"://"+origHostPort] || s.allowedOrigins[strings.ToLower(origin)]) {
		return true
	}
	if !s.isAllowedHost(origRawHost) {
		return false
	}
	reqScheme, reqHostPort := s.effectiveRequestOrigin(r)
	return origScheme == reqScheme && origHostPort == reqHostPort
}

func isJSONContentType(r *http.Request) bool {
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/json")
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	if !isJSONContentType(r) {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Unsupported Media Type: Content-Type must be application/json")
		return false
	}
	return true
}

func decodeLimitedJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			w.Write([]byte(`{"error": "Request body too large"}` + "\n"))
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Invalid JSON request body"}` + "\n"))
		return false
	}
	return true
}

// extractHeaderToken extracts credentials from Authorization or X-API-Key headers only (never URL query parameters).
func extractHeaderToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if keyHeader := r.Header.Get("X-API-Key"); keyHeader != "" {
		return strings.TrimSpace(keyHeader)
	}
	return ""
}

// Top-level security middleware enforcing security headers, Host allowlist, and Origin checks.
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Standard defensive security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/v2/") || r.URL.Path == "/admin" || r.URL.Path == "/keys" {
			w.Header().Set("Cache-Control", "no-store")
		}

		if !s.isAllowedHost(r.Host) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Forbidden: untrusted Host header."}` + "\n"))
			return
		}

		// Reject query-string tokens on any non-WebSocket request so secrets never leak in URLs/logs
		isWSUpgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && (r.URL.Path == "/v1/receive" || strings.HasPrefix(r.URL.Path, "/v1/receive/"))
		if !isWSUpgrade && r.URL.Query().Get("token") != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Bad Request: token query parameter is only permitted on WebSocket upgrades."}` + "\n"))
			return
		}

		// Validate Origin on WebSocket upgrades and state-changing requests
		if isWSUpgrade || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions) {
			if !s.isAllowedOrigin(r) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error": "Forbidden: untrusted Origin header."}` + "\n"))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Client authentication middleware: requires a scoped client API key (or Basic Auth / explicit ALLOW_UNAUTHENTICATED).
// ?token= is only accepted on WebSocket upgrades and only for scoped client keys (never the root admin key).
func (s *Server) clientAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Publicly exempt paths
		if path == "/v1/health" || path == "/openapi.json" || path == "/swagger.json" ||
			path == "/docs" || path == "/docs.js" || path == "/swagger" ||
			path == "/admin" || path == "/admin.js" || path == "/keys" || path == "/keys.js" || path == "/admin/keys" {
			next(w, r)
			return
		}

		// Security: Block HTTP registration & unregistration
		if strings.HasPrefix(path, "/v1/register") || strings.HasPrefix(path, "/v1/unregister") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Forbidden: Signal account registration via HTTP is disabled for security. Use container terminal."}` + "\n"))
			return
		}

		headerToken := extractHeaderToken(r)
		isWSUpgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && (path == "/v1/receive" || strings.HasPrefix(path, "/v1/receive/"))

		candidateToken := headerToken
		usedQueryToken := false
		if candidateToken == "" && isWSUpgrade {
			if qt := strings.TrimSpace(r.URL.Query().Get("token")); qt != "" {
				candidateToken = qt
				usedQueryToken = true
			}
		}

		// Reject root key in ?token= query parameter unconditionally
		if usedQueryToken && s.apiKeyMgmt != "" && constantTimeEquals(candidateToken, s.apiKeyMgmt) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Unauthorized: root admin key is not permitted in query parameters."}` + "\n"))
			return
		}

		// 1. Scoped Client API Key
		if s.keyStore != nil && candidateToken != "" {
			if k, ok := s.keyStore.LookupKey(candidateToken); ok {
				p := &AuthPrincipal{
					IsRoot:      false,
					KeyID:       k.ID,
					Accounts:    k.Accounts,
					Permissions: k.Permissions,
					CreatedAt:   k.CreatedAt,
				}
				next(w, r.WithContext(context.WithValue(r.Context(), principalContextKey, p)))
				return
			}
		}

		// 2. Active short-lived Admin Session
		if headerToken != "" && s.sessionStore != nil && s.sessionStore.ValidateSession(headerToken) {
			p := &AuthPrincipal{
				IsRoot:       true,
				KeyID:        "session:" + headerToken,
				SessionToken: headerToken,
				Accounts:     []string{"*"},
				Permissions:  []string{PermSend, PermReceive, PermAdmin},
			}
			next(w, r.WithContext(context.WithValue(r.Context(), principalContextKey, p)))
			return
		}

		// 3. Explicit unauthenticated mode ONLY when ALLOW_UNAUTHENTICATED=true
		if s.allowUnauthenticated {
			principal := &AuthPrincipal{
				IsRoot:      true,
				KeyID:       "unauth:" + s.realClientIP(r),
				Accounts:    []string{"*"},
				Permissions: []string{PermSend, PermReceive, PermAdmin},
			}
			next(w, r.WithContext(context.WithValue(r.Context(), principalContextKey, principal)))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="Signal API"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Unauthorized: Invalid or missing client API key."}` + "\n"))
	}
}

// Admin authentication middleware: requires an active, non-idle Admin Session Token (< 3 min hard TTL, < 2 min idle).
// Header-only (never accepts ?token=).
func (s *Server) adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractHeaderToken(r)

		if s.apiKeyMgmt == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Key management disabled: API_KEY_MGMT environment variable is not configured."}` + "\n"))
			return
		}

		// Valid if an unexpired, non-idle short-lived admin session
		if s.sessionStore != nil && s.sessionStore.ValidateSession(token) {
			p := &AuthPrincipal{
				IsRoot:      true,
				Accounts:    []string{"*"},
				Permissions: []string{PermSend, PermReceive, PermAdmin},
			}
			next(w, r.WithContext(context.WithValue(r.Context(), principalContextKey, p)))
			return
		}

		// Also allow a client API key explicitly granted "admin" permission for /api/accounts/profile or /v1/profiles
		if (r.URL.Path == "/api/accounts/profile" || r.URL.Path == "/v1/profiles" || strings.HasPrefix(r.URL.Path, "/v1/profiles/")) && s.keyStore != nil && token != "" {
			if k, ok := s.keyStore.LookupKey(token); ok && k.HasPermission(PermAdmin) {
				p := &AuthPrincipal{
					IsRoot:      false,
					KeyID:       k.ID,
					Accounts:    k.Accounts,
					Permissions: k.Permissions,
					CreatedAt:   k.CreatedAt,
				}
				next(w, r.WithContext(context.WithValue(r.Context(), principalContextKey, p)))
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="Signal API Admin"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Unauthorized: Valid admin session token required (authenticate via POST /api/auth/login)."}` + "\n"))
	}
}

// Generates a short-lived ephemeral session token for the Key Management UI & API
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSON(w, r) {
		return
	}

	if s.apiKeyMgmt == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Key management disabled: API_KEY_MGMT is not configured."}` + "\n"))
		return
	}

	ip := s.realClientIP(r)
	if s.loginLimiter != nil && s.loginLimiter.IsLocked(ip) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "Too many failed login attempts. Try again later."}` + "\n"))
		return
	}

	var req struct {
		AdminKey string `json:"admin_key"`
	}
	if !decodeLimitedJSON(w, r, maxAuthBodyBytes, &req) {
		return
	}

	token := strings.TrimSpace(req.AdminKey)
	if token == "" {
		token = extractHeaderToken(r)
	}

	if !constantTimeEquals(token, s.apiKeyMgmt) {
		var delay time.Duration
		var rateLimited bool
		if s.loginLimiter != nil {
			delay, rateLimited = s.loginLimiter.ThrottleFailure(ip)
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-r.Context().Done():
				timer.Stop()
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if rateLimited {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "Too many failed login attempts. Try again later."}` + "\n"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Invalid root admin key (API_KEY_MGMT required)."}` + "\n"))
		return
	}

	if s.loginLimiter != nil {
		s.loginLimiter.Reset(ip)
	}

	sessionToken, ttlSeconds := s.sessionStore.CreateSession()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      sessionToken,
		"expires_in": ttlSeconds, // 180 seconds (3 minutes, with 2-minute server-side idle lock)
	})
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := extractHeaderToken(r)
	s.sessionStore.RevokeSession(token)
	if s.hub != nil {
		s.hub.DisconnectSession(token)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "logged_out"}` + "\n"))
}

// Key Management Handlers
func (s *Server) handleListOrAddKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		keys := s.keyStore.ListKeys()
		json.NewEncoder(w).Encode(keys)

	case http.MethodPost:
		if !requireJSON(w, r) {
			return
		}
		var req struct {
			Name          string     `json:"name"`
			Accounts      []string   `json:"accounts"`
			Permissions   []string   `json:"permissions"`
			ExpiresAt     *time.Time `json:"expires_at"`
			ExpiresInDays int        `json:"expires_in_days"`
		}
		if !decodeLimitedJSON(w, r, maxAuthBodyBytes, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			http.Error(w, `{"error": "Name, accounts, and permissions fields are required"}`, http.StatusBadRequest)
			return
		}

		expiresAt := req.ExpiresAt
		if expiresAt == nil && req.ExpiresInDays > 0 {
			if req.ExpiresInDays > 3650 {
				writeJSONError(w, http.StatusBadRequest, "expires_in_days cannot exceed 3650 days")
				return
			}
			exp := time.Now().UTC().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
			expiresAt = &exp
		}

		newKey, err := s.keyStore.CreateKeyWithExpiry(strings.TrimSpace(req.Name), req.Accounts, req.Permissions, expiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newKey)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	keyID := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	if !keyIDRegex.MatchString(keyID) {
		writeJSONError(w, http.StatusBadRequest, "Missing or invalid key ID")
		return
	}

	revoked, err := s.keyStore.RevokeKey(keyID)
	if err != nil {
		log.Printf("[keystore] Error revoking key %q: %v", keyID, err)
		writeJSONError(w, http.StatusInternalServerError, "Failed to persist key revocation")
		return
	}
	if revoked {
		if s.hub != nil {
			s.hub.DisconnectKey(keyID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "revoked"}` + "\n"))
	} else {
		writeJSONError(w, http.StatusNotFound, "Key not found")
	}
}

// listAuthorizedAccounts returns the registered Signal accounts that the given principal is allowed to access.
func (s *Server) listAuthorizedAccounts(principal *AuthPrincipal) ([]string, error) {
	if s.daemon == nil {
		return nil, errors.New("daemon unavailable")
	}
	var allAccounts []string
	result, err := s.daemon.call("listAccounts", nil)
	if err != nil {
		// If daemon is not connected yet, return scoped accounts for non-root keys without spawning a CLI subprocess
		if principal != nil && !principal.IsRoot && !principal.AllowsAccount("*") {
			return principal.Accounts, nil
		}
		return nil, err
	}

	var strSlice []string
	if err := json.Unmarshal(result, &strSlice); err == nil {
		allAccounts = strSlice
	} else {
		var objSlice []struct {
			Number string `json:"number"`
			UUID   string `json:"uuid"`
		}
		if err := json.Unmarshal(result, &objSlice); err == nil {
			for _, item := range objSlice {
				if item.Number != "" {
					allAccounts = append(allAccounts, item.Number)
				} else if item.UUID != "" {
					allAccounts = append(allAccounts, item.UUID)
				}
			}
		}
	}

	filtered := make([]string, 0, len(allAccounts))
	for _, acc := range allAccounts {
		if principal == nil || principal.AllowsAccount(acc) {
			filtered = append(filtered, acc)
		}
	}
	return filtered, nil
}

// resolveAccount validates an explicit account identifier or, when omitted, automatically resolves
// the single unambiguous account (either from a single-account scoped API key or a single registered Signal account).
func (s *Server) resolveAccount(explicit string, principal *AuthPrincipal) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		if !isValidAccountIdentifier(explicit) {
			return "", errors.New("Missing or invalid account identifier")
		}
		return explicit, nil
	}

	// 1. If the caller's API key is scoped to exactly one concrete account, use it directly
	if principal != nil {
		var concrete []string
		hasWildcard := false
		for _, acc := range principal.Accounts {
			acc = strings.TrimSpace(acc)
			if acc == "*" {
				hasWildcard = true
				break
			}
			if isValidAccountIdentifier(acc) {
				concrete = append(concrete, acc)
			}
		}
		if !hasWildcard && len(concrete) == 1 {
			return concrete[0], nil
		}
	}

	// 2. Otherwise query signal-cli for registered accounts authorized for this principal
	accounts, err := s.listAuthorizedAccounts(principal)
	if err == nil && len(accounts) == 1 && isValidAccountIdentifier(accounts[0]) {
		return strings.TrimSpace(accounts[0]), nil
	}

	return "", errors.New("Missing or invalid account identifier")
}

// Signal Operational Endpoints
func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	principal := getPrincipal(r)
	if !principal.HasPermission(PermReceive) && !principal.HasPermission(PermSend) {
		writeJSONError(w, http.StatusForbidden, "Forbidden: key lacks permission to list accounts.")
		return
	}

	filtered, err := s.listAuthorizedAccounts(principal)
	if err != nil {
		log.Printf("[server] listAccounts failed: %v", err)
		writeJSONError(w, http.StatusBadGateway, "Upstream signal-cli daemon unavailable")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	principal := getPrincipal(r)
	rawAccount := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/v1/groups/"), "/v1/groups")
	account, err := s.resolveAccount(rawAccount, principal)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !principal.HasPermission(PermReceive) || !principal.AllowsAccount(account) {
		writeJSONError(w, http.StatusForbidden, "Forbidden: key is not authorized for this account or lacks receive permission.")
		return
	}

	params := map[string]interface{}{"account": account}
	result, err := s.daemon.call("listGroups", params)
	if err != nil {
		log.Printf("[server] listGroups failed: %v", err)
		writeJSONError(w, http.StatusBadGateway, "Failed to retrieve groups from signal-cli daemon")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

type ReactionRequest struct {
	Recipient    string `json:"recipient"`
	Reaction     string `json:"reaction"`
	TargetAuthor string `json:"target_author"`
	Timestamp    int64  `json:"timestamp"`
	Remove       bool   `json:"remove"`
}

func (s *Server) handleReactions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !requireJSON(w, r) {
		return
	}

	principal := getPrincipal(r)
	rawAccount := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/v1/reactions/"), "/v1/reactions")
	account, err := s.resolveAccount(rawAccount, principal)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !principal.HasPermission(PermSend) || !principal.AllowsAccount(account) {
		writeJSONError(w, http.StatusForbidden, "Forbidden: key is not authorized to send for this account.")
		return
	}

	var req ReactionRequest
	if !decodeLimitedJSON(w, r, maxRequestBodyBytes, &req) {
		return
	}
	if !isValidRecipientIdentifier(req.Recipient) || !isValidAccountIdentifier(req.TargetAuthor) || strings.TrimSpace(req.Reaction) == "" || req.Timestamp <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Invalid recipient, target_author, reaction, or timestamp")
		return
	}

	if s.sendLimiter != nil && !s.sendLimiter.Allow(account) {
		writeJSONError(w, http.StatusTooManyRequests, "Too Many Requests: rate limit exceeded for account.")
		return
	}

	params := map[string]interface{}{
		"account":         account,
		"emoji":           req.Reaction,
		"targetAuthor":    req.TargetAuthor,
		"targetTimestamp": req.Timestamp,
		"remove":          req.Remove,
	}

	if isGroupRecipient(req.Recipient) {
		params["groupId"] = normalizeGroupID(req.Recipient)
	} else {
		params["recipient"] = []string{strings.TrimSpace(req.Recipient)}
	}

	if _, err := s.daemon.call("sendReaction", params); err != nil {
		log.Printf("[server] Failed to send reaction: %v", err)
		writeJSONError(w, http.StatusBadGateway, "Failed to send reaction via signal-cli daemon")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type SendRequest struct {
	Number     string   `json:"number"`
	Account    string   `json:"account"`
	Recipients []string `json:"recipients"`
	Message    string   `json:"message"`
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !requireJSON(w, r) {
		return
	}

	var req SendRequest
	if !decodeLimitedJSON(w, r, maxRequestBodyBytes, &req) {
		return
	}
	principal := getPrincipal(r)
	explicitAccount := strings.TrimSpace(req.Number)
	if explicitAccount == "" {
		explicitAccount = strings.TrimSpace(req.Account)
	}
	senderAccount, err := s.resolveAccount(explicitAccount, principal)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Missing or invalid sender account identifier")
		return
	}
	req.Number = senderAccount

	if len(req.Recipients) == 0 || len(req.Recipients) > 50 {
		writeJSONError(w, http.StatusBadRequest, "Between 1 and 50 valid recipients are required")
		return
	}
	for _, rcpt := range req.Recipients {
		if !isValidRecipientIdentifier(rcpt) {
			writeJSONError(w, http.StatusBadRequest, "Invalid recipient identifier")
			return
		}
	}

	if !principal.HasPermission(PermSend) || !principal.AllowsAccount(req.Number) {
		writeJSONError(w, http.StatusForbidden, "Forbidden: key is not authorized to send as this account.")
		return
	}

	if s.sendLimiter != nil && !s.sendLimiter.Allow(req.Number) {
		writeJSONError(w, http.StatusTooManyRequests, "Too Many Requests: send rate limit exceeded for account.")
		return
	}

	var directRecipients []string
	var groupIDs []string
	for _, rcpt := range req.Recipients {
		if isGroupRecipient(rcpt) {
			groupIDs = append(groupIDs, normalizeGroupID(rcpt))
		} else {
			directRecipients = append(directRecipients, strings.TrimSpace(rcpt))
		}
	}

	params := map[string]interface{}{
		"account": req.Number,
		"message": req.Message,
	}
	if len(directRecipients) > 0 {
		params["recipient"] = directRecipients
	}
	if len(groupIDs) == 1 {
		params["groupId"] = groupIDs[0]
	} else if len(groupIDs) > 1 {
		params["groupId"] = groupIDs
	}

	res, err := s.daemon.call("send", params)
	if err != nil {
		log.Printf("[server] Failed to send message: %v", err)
		writeJSONError(w, http.StatusBadGateway, "Failed to send message via signal-cli daemon")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(res)
}

func (s *Server) handleReceive(w http.ResponseWriter, r *http.Request) {
	rawAccount := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/v1/receive/"), "/v1/receive")
	if strings.Contains(rawAccount, "?") {
		rawAccount = strings.Split(rawAccount, "?")[0]
	}
	principal := getPrincipal(r)
	account, err := s.resolveAccount(rawAccount, principal)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !principal.HasPermission(PermReceive) || !principal.AllowsAccount(account) {
		writeJSONError(w, http.StatusForbidden, "Forbidden: key is not authorized to receive messages for this account.")
		return
	}

	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		if !s.isAllowedOrigin(r) {
			writeJSONError(w, http.StatusForbidden, "Forbidden: untrusted Origin header.")
			return
		}
		_, err := upgradeWebSocket(w, r, account, principal.KeyID, principal.SessionToken, s.hub)
		if err != nil {
			if errors.Is(err, errWSLimitExceeded) {
				writeJSONError(w, http.StatusTooManyRequests, "Too Many Requests: WebSocket connection limit exceeded.")
				return
			}
			log.Printf("[server] WebSocket upgrade error: %v", err)
		}
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		items := s.hub.GetHistory(account, principal.CreatedAt)
		json.NewEncoder(w).Encode(items)
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var account, givenName, familyName string
	var avatarBytes []byte
	var avatarExt string

	pathAccount := ""
	if strings.HasPrefix(r.URL.Path, "/v1/profiles/") {
		pathAccount = strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/profiles/"))
	}

	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType, _, _ := mime.ParseMediaType(ct)

	if strings.EqualFold(mediaType, "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, maxProfileBodyBytes)
		if err := r.ParseMultipartForm(maxProfileBodyBytes); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				writeJSONError(w, http.StatusRequestEntityTooLarge, "Request body too large")
				return
			}
			writeJSONError(w, http.StatusBadRequest, "Invalid multipart form request")
			return
		}
		account = strings.TrimSpace(r.FormValue("account"))
		givenName = strings.TrimSpace(r.FormValue("given_name"))
		if givenName == "" {
			givenName = strings.TrimSpace(r.FormValue("name"))
		}
		familyName = strings.TrimSpace(r.FormValue("family_name"))

		file, _, err := r.FormFile("avatar")
		if err == nil {
			defer file.Close()
			rawBytes, readErr := io.ReadAll(io.LimitReader(file, maxAvatarBytes+1))
			if readErr != nil {
				writeJSONError(w, http.StatusBadRequest, "Failed to read uploaded avatar file")
				return
			}
			sanitized, ext, valErr := sanitizeAvatarBytes(rawBytes)
			if valErr != nil {
				writeJSONError(w, http.StatusBadRequest, valErr.Error())
				return
			}
			avatarBytes = sanitized
			avatarExt = ext
		} else if !errors.Is(err, http.ErrMissingFile) {
			writeJSONError(w, http.StatusBadRequest, "Invalid avatar file upload")
			return
		}
	} else {
		if !requireJSON(w, r) {
			return
		}
		var req struct {
			Account    string `json:"account"`
			GivenName  string `json:"given_name"`
			Name       string `json:"name"`
			FamilyName string `json:"family_name"`
			Avatar     string `json:"avatar"`
		}
		if !decodeLimitedJSON(w, r, maxProfileBodyBytes, &req) {
			return
		}
		account = strings.TrimSpace(req.Account)
		givenName = strings.TrimSpace(req.GivenName)
		if givenName == "" {
			givenName = strings.TrimSpace(req.Name)
		}
		familyName = strings.TrimSpace(req.FamilyName)
		if strings.TrimSpace(req.Avatar) != "" {
			decoded, ext, err := decodeAvatarData(req.Avatar)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			avatarBytes = decoded
			avatarExt = ext
		}
	}

	if account == "" {
		account = pathAccount
	}
	principal := getPrincipal(r)
	resolvedAccount, err := s.resolveAccount(account, principal)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	account = resolvedAccount

	if !principal.HasPermission(PermAdmin) || !principal.AllowsAccount(account) {
		writeJSONError(w, http.StatusForbidden, "Forbidden: admin permission for this account is required to update profile.")
		return
	}

	if !isValidProfileName(givenName, true) {
		writeJSONError(w, http.StatusBadRequest, "Invalid or missing given_name (1-64 characters, must not start with '-' or contain control characters)")
		return
	}
	if !isValidProfileName(familyName, false) {
		writeJSONError(w, http.StatusBadRequest, "Invalid family_name (up to 64 characters, must not start with '-' or contain control characters)")
		return
	}

	var avatarPath string
	if len(avatarBytes) > 0 {
		tmpFile, err := os.CreateTemp("", "signal-avatar-*"+avatarExt)
		if err != nil {
			log.Printf("[server] Failed to create temporary avatar file: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "Failed to stage profile avatar")
			return
		}
		avatarPath = tmpFile.Name()
		defer os.Remove(avatarPath)

		if _, err := tmpFile.Write(avatarBytes); err != nil {
			_ = tmpFile.Close()
			log.Printf("[server] Failed to write temporary avatar file: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "Failed to write profile avatar")
			return
		}
		if err := tmpFile.Close(); err != nil {
			log.Printf("[server] Failed to close temporary avatar file: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "Failed to finalize profile avatar")
			return
		}
	}

	if s.profileUpdater != nil {
		_, err = s.profileUpdater(r.Context(), account, givenName, familyName, avatarPath)
	} else {
		params := buildUpdateProfileParams(account, givenName, familyName, avatarPath)
		_, err = s.daemon.call("updateProfile", params)
	}
	if err != nil {
		log.Printf("[server] Failed to update profile for %q: %v", account, err)
		writeJSONError(w, http.StatusBadGateway, "Failed to update account profile via signal-cli daemon")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "profile_updated",
		"account": account,
	})
}

func (s *Server) Handler() http.Handler {
	if len(s.allowedHosts) == 0 {
		s.allowedHosts = defaultAllowedHosts(os.Getenv("ALLOWED_HOSTS"))
	}
	if len(s.trustedProxies) == 0 {
		s.trustedProxies = parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	}
	if s.trustedProxyHeader == "" {
		s.trustedProxyHeader = strings.TrimSpace(os.Getenv("TRUSTED_PROXY_HEADER"))
	}
	if s.loginLimiter == nil {
		s.loginLimiter = newRateLimiter(5, 5*time.Minute)
	}
	if s.sendLimiter == nil {
		s.sendLimiter = newRateLimiter(30, time.Minute)
	}
	if s.hub != nil {
		s.hub.mu.Lock()
		if s.sessionStore != nil {
			s.hub.sessionValidator = s.sessionStore.IsSessionActive
		}
		if s.keyStore != nil {
			s.hub.keyValidator = s.keyStore.IsKeyActive
		}
		s.hub.mu.Unlock()
		if s.sessionStore != nil {
			s.sessionStore.OnSessionEnd(s.hub.DisconnectSession)
		}
	}

	mux := http.NewServeMux()

	// OpenAPI & Docs
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "openapi.json")
	})
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "openapi.json")
	})
	mux.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "docs.html")
	})
	mux.HandleFunc("/docs.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		http.ServeFile(w, r, "docs.js")
	})
	mux.HandleFunc("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
	})

	// Admin UI (/admin) & backwards-compatible /keys redirects
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "admin.html")
	})
	mux.HandleFunc("/admin.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		http.ServeFile(w, r, "admin.js")
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/keys.js", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin.js", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/admin/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusMovedPermanently)
	})

	// Admin Authentication (3-minute short-lived session with 2-minute idle timeout)
	mux.HandleFunc("/api/auth/login", s.handleAdminLogin)
	mux.HandleFunc("/api/auth/logout", s.handleAdminLogout)

	// Admin Endpoints: Account Profile & API Key Management (Requires valid 3-minute session token)
	mux.HandleFunc("/api/accounts/profile", s.adminAuthMiddleware(s.handleUpdateProfile))
	mux.HandleFunc("/v1/profiles", s.adminAuthMiddleware(s.handleUpdateProfile))
	mux.HandleFunc("/v1/profiles/", s.adminAuthMiddleware(s.handleUpdateProfile))
	mux.HandleFunc("/api/keys", s.adminAuthMiddleware(s.handleListOrAddKeys))
	mux.HandleFunc("/api/keys/", s.adminAuthMiddleware(s.handleRevokeKey))
	mux.HandleFunc("/api/info", s.adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version": effectiveVersion(),
		})
	}))

	// Health check
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}` + "\n"))
	})

	// Signal API Operational Endpoints (Requires valid Scoped Client API Key)
	mux.HandleFunc("/v1/accounts", s.clientAuthMiddleware(s.handleAccounts))
	mux.HandleFunc("/v1/groups", s.clientAuthMiddleware(s.handleGroups))
	mux.HandleFunc("/v1/groups/", s.clientAuthMiddleware(s.handleGroups))
	mux.HandleFunc("/v1/reactions", s.clientAuthMiddleware(s.handleReactions))
	mux.HandleFunc("/v1/reactions/", s.clientAuthMiddleware(s.handleReactions))
	mux.HandleFunc("/v2/send", s.clientAuthMiddleware(s.handleSend))
	mux.HandleFunc("/v1/receive", s.clientAuthMiddleware(s.handleReceive))
	mux.HandleFunc("/v1/receive/", s.clientAuthMiddleware(s.handleReceive))

	// Block registration endpoints over HTTP
	mux.HandleFunc("/v1/register", s.clientAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("/v1/unregister", s.clientAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {}))

	return s.securityMiddleware(mux)
}

var weakRootKeys = map[string]bool{
	"your_super_secret_root_mgmt_key_here": true,
	"changeme":                             true,
	"password":                             true,
	"secret":                               true,
	"admin":                                true,
}

func hasSufficientKeyEntropy(val string) bool {
	seen := make(map[rune]struct{}, len(val))
	for _, r := range val {
		seen[r] = struct{}{}
	}
	return len(seen) >= 6
}

func validateStartupConfig(apiKeyMgmt string, allowUnauthenticated bool) error {
	trimmed := strings.TrimSpace(apiKeyMgmt)
	if trimmed == "" {
		if allowUnauthenticated {
			return nil
		}
		return errors.New("refusing to start without API_KEY_MGMT configured (set API_KEY_MGMT or explicitly set ALLOW_UNAUTHENTICATED=true)")
	}
	if len(trimmed) < minRootKeyLength || weakRootKeys[strings.ToLower(trimmed)] || !hasSufficientKeyEntropy(trimmed) {
		return fmt.Errorf("refusing to start: API_KEY_MGMT must be at least %d characters with sufficient entropy and not a default placeholder", minRootKeyLength)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Main Entrypoint
// -----------------------------------------------------------------------------

func runHealthcheck(baseURL string) error {
	return runHealthcheckWithClient(baseURL, &http.Client{Timeout: 3 * time.Second})
}

func runHealthcheckWithClient(baseURL string, client *http.Client) error {
	if strings.TrimSpace(baseURL) == "" {
		port := strings.TrimSpace(os.Getenv("PORT"))
		if port == "" {
			port = defaultPort
		}
		baseURL = "http://127.0.0.1:" + port
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/v1/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected health status %d", resp.StatusCode)
	}
	return nil
}

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "healthcheck" || os.Args[1] == "-healthcheck" || os.Args[1] == "--healthcheck") {
		if err := runHealthcheck(""); err != nil {
			fmt.Fprintf(os.Stderr, "Healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "register-recovery" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: signal-api register-recovery <account_id> [--reregister] [--voice] [--captcha <token>]")
			os.Exit(2)
		}
		if err := runRegisterRecovery(os.Args[2], os.Stdin, os.Args[3:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Registration request completed successfully.")
		return
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// Root admin key
	apiKeyMgmt := strings.TrimSpace(os.Getenv("API_KEY_MGMT"))
	if apiKeyMgmt == "" {
		// Backwards-compatibility fallback if API_KEY was passed
		apiKeyMgmt = strings.TrimSpace(os.Getenv("API_KEY"))
	}

	allowUnauth := strings.EqualFold(strings.TrimSpace(os.Getenv("ALLOW_UNAUTHENTICATED")), "true")
	if err := validateStartupConfig(apiKeyMgmt, allowUnauth); err != nil {
		log.Fatalf("[server] %v", err)
	}

	keyStorePath := configDir + "/api_keys.json"
	keyStore, err := newKeyStore(keyStorePath)
	if err != nil {
		log.Fatalf("[keystore] Fatal error loading %s: %v", keyStorePath, err)
	}

	sessionStore := newSessionStore(defaultSessionTTL)

	hub := newWSHub()
	go hub.run()

	daemon := newSignalDaemon(hub)
	daemon.start()

	srv := &Server{
		daemon:               daemon,
		hub:                  hub,
		keyStore:             keyStore,
		sessionStore:         sessionStore,
		apiKeyMgmt:           apiKeyMgmt,
		allowUnauthenticated: allowUnauth,
		allowedHosts:         defaultAllowedHosts(os.Getenv("ALLOWED_HOSTS")),
		allowedOrigins:       parseAllowedOrigins(os.Getenv("ALLOWED_ORIGINS")),
		trustedProxyHeader:   strings.TrimSpace(os.Getenv("TRUSTED_PROXY_HEADER")),
		trustedProxies:       parseTrustedProxies(os.Getenv("TRUSTED_PROXIES")),
		loginLimiter:         newRateLimiter(5, 5*time.Minute),
		sendLimiter:          newRateLimiter(30, time.Minute),
	}

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[server] Signal CLI REST API starting on port %s", port)
		if apiKeyMgmt != "" {
			log.Println("[server] Root Admin Key (API_KEY_MGMT): CONFIGURED")
			log.Printf("[server] Admin UI available at: http://localhost:%s/admin", port)
		} else {
			log.Println("[server] WARNING: Running in explicit ALLOW_UNAUTHENTICATED=true mode!")
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[server] Listen error: %v", err)
		}
	}()

	<-stop
	log.Println("[server] Shutting down gracefully...")
	_ = httpServer.Close()
	_ = keyStore.FlushLastUsed()
	daemon.stop()
}
