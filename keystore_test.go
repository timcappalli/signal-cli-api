package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testRootKey = "root_admin_secret_key_0123456789"

func createAdminSession(t *testing.T, handler http.Handler, rootKey string) string {
	t.Helper()
	body := bytes.NewBufferString(`{"admin_key":"` + rootKey + `"}`)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Failed to login as admin: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Token
}

// Issues 1, 7, 8: KeyStore hashing, independent ID, atomic save, revocation failure handling, and corrupt file rejection
func TestKeyStoreHashingAndAtomicPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "api_keys.json")

	ks, err := newKeyStore(filePath)
	if err != nil {
		t.Fatalf("Expected missing file to initialize empty keystore, got error: %v", err)
	}

	// Create scoped key for a service
	key1, err := ks.CreateKey("IETF Moderator", []string{"+15551112222"}, []string{"send", "receive"})
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	if !strings.HasPrefix(key1.Key, "sig_") {
		t.Errorf("Expected key to start with sig_, got %s", key1.Key)
	}

	// Issue 7: Verify ID is independent of secret bytes
	idHex := strings.TrimPrefix(key1.ID, "key_")
	secretHex := strings.TrimPrefix(key1.Key, "sig_")
	if strings.HasPrefix(secretHex, idHex) {
		t.Errorf("Expected key ID (%s) to be generated independently of secret (%s)", idHex, secretHex)
	}

	// Issue 7: Verify plaintext secret is NOT stored in api_keys.json on disk (only SHA-256 key_hash)
	rawDisk, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawDisk), key1.Key) {
		t.Fatalf("Plaintext client key was written to api_keys.json!")
	}
	expectedHash := hashSecret(key1.Key)
	if !strings.Contains(string(rawDisk), expectedHash) {
		t.Fatalf("Expected SHA-256 key_hash %s in api_keys.json, got: %s", expectedHash, string(rawDisk))
	}
	_ = hex.DecodeString

	// Reload from disk and verify hash lookup works
	ks2, err := newKeyStore(filePath)
	if err != nil {
		t.Fatalf("Failed to reload keystore: %v", err)
	}
	if !ks2.ValidateKey(key1.Key, testRootKey) {
		t.Errorf("Expected key to validate via SHA-256 hash across reload")
	}

	// Issue 8: Revoke key persists atomically
	revoked, err := ks2.RevokeKey(key1.ID)
	if err != nil || !revoked {
		t.Fatalf("Failed to revoke key: revoked=%v err=%v", revoked, err)
	}
	if ks2.ValidateKey(key1.Key, testRootKey) {
		t.Errorf("Expected revoked key to no longer be valid")
	}

	// Issue 1: Corrupt api_keys.json must return an error rather than loading 0 keys
	corruptPath := filepath.Join(tmpDir, "corrupt_keys.json")
	if err := os.WriteFile(corruptPath, []byte("{corrupt json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newKeyStore(corruptPath); err == nil {
		t.Errorf("Expected corrupt api_keys.json to return an error, got nil")
	}
}

// Issue 6: SessionStore enforces both hard TTL and server-side inactivity timeout
func TestSessionStoreHardAndIdleTimeouts(t *testing.T) {
	// ttl = 300ms, idleTimeout = 200ms
	ss := newSessionStore(300 * time.Millisecond)

	token, _ := ss.CreateSession()
	if !ss.ValidateSession(token) {
		t.Fatalf("Expected fresh session token to be valid")
	}

	// Wait 220ms (> 200ms idleTimeout, < 300ms hard TTL) without activity
	time.Sleep(220 * time.Millisecond)
	if ss.ValidateSession(token) {
		t.Errorf("Expected session token to expire due to server-side inactivity timeout")
	}
}

// Issue 1 & 6: Fails closed without credentials and rejects weak/placeholder root keys
func TestStartupValidationAndFailClosed(t *testing.T) {
	if err := validateStartupConfig("", false); err == nil {
		t.Errorf("Expected validateStartupConfig to reject empty API_KEY_MGMT")
	}
	if err := validateStartupConfig("short_key", false); err == nil {
		t.Errorf("Expected validateStartupConfig to reject short API_KEY_MGMT (< 16 chars)")
	}
	if err := validateStartupConfig("your_super_secret_root_mgmt_key_here", false); err == nil {
		t.Errorf("Expected validateStartupConfig to reject default .env.example placeholder")
	}
	if err := validateStartupConfig("aaaaaaaaaaaaaaaaaaaa", false); err == nil {
		t.Errorf("Expected validateStartupConfig to reject low-entropy repeated-character root key")
	}
	if err := validateStartupConfig(testRootKey, false); err != nil {
		t.Errorf("Expected strong root key to pass validation: %v", err)
	}

	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	hub := newWSHub()
	go hub.run()

	srv := &Server{
		hub:                  hub,
		keyStore:             ks,
		sessionStore:         newSessionStore(time.Minute),
		apiKeyMgmt:           "",
		allowUnauthenticated: false,
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized when no credentials are set, got %d", rec.Code)
	}
}

type pipeHijackRecorder struct {
	*httptest.ResponseRecorder
	serverConn net.Conn
	hijacked   bool
}

func (p *pipeHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	p.hijacked = true
	rw := bufio.NewReadWriter(bufio.NewReader(p.serverConn), bufio.NewWriter(p.serverConn))
	return p.serverConn, rw, nil
}

// Issue 2 & 6: WebSocket oversized frame protection and ?token= restricted to client keys on WS upgrade
func TestWebSocketOversizedFrameAndQueryTokenRestrictions(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	clientKey, err := ks.CreateKey("WS Client", []string{"+15551234567"}, []string{"receive"})
	if err != nil {
		t.Fatal(err)
	}
	hub := newWSHub()
	go hub.run()

	srv := &Server{
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	// 1. ?token= on regular HTTP GET is rejected (400 Bad Request)
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567?token="+clientKey.Key, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected ?token= on non-WebSocket HTTP GET to return 400, got %d", rec.Code)
	}

	// 2. ?token= with root key on WebSocket upgrade is rejected (401 Unauthorized)
	req = httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567?token="+testRootKey, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected root key in ?token= on WS upgrade to return 401, got %d", rec.Code)
	}

	// 3. Valid client key in ?token= on WS upgrade succeeds, and 64-bit 0xFFFFFFFFFFFFFFFF frame is safely rejected
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	req = httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567?token="+clientKey.Key, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	pipeRec := &pipeHijackRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		serverConn:       serverConn,
	}

	go handler.ServeHTTP(pipeRec, req)

	reader := bufio.NewReader(clientConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		t.Fatalf("Expected 101 Switching Protocols, got %q (err=%v)", statusLine, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	maliciousFrame := []byte{0x81, 0xFF}
	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, 0xFFFFFFFFFFFFFFFF)
	maliciousFrame = append(maliciousFrame, lenBytes...)
	maliciousFrame = append(maliciousFrame, 0x00, 0x00, 0x00, 0x00)

	go func() {
		_, _ = clientConn.Write(maliciousFrame)
	}()

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b1, err := reader.ReadByte()
	if err != nil {
		t.Fatalf("Expected close frame from server, got error: %v", err)
	}
	if b1&0x0F != 0x08 {
		t.Errorf("Expected close opcode 0x08, got 0x%x", b1&0x0F)
	}
}

// Issue 3 & 9: Key scoping by account, permissions, key creation timestamp, and strict input validation
func TestKeyScopingHistoryAndInputValidation(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	hub := newWSHub()
	go hub.run()

	acctA := "+15550001111"
	acctB := "+15550002222"

	// Publish a pre-existing message to acctA BEFORE creating the key
	hub.Publish("", []byte(`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"message":"before-key"}}}`))
	hub.Publish("", []byte(`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550002222","envelope":{"message":"acctB-msg"}}}`))

	time.Sleep(20 * time.Millisecond)

	keyA, err := ks.CreateKey("Service A Receive Only", []string{acctA}, []string{"receive"})
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := ks.CreateKey("Service B Send Only", []string{acctB}, []string{"send"})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)

	// Publish a message to acctA AFTER keyA was created
	hub.Publish("", []byte(`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"message":"after-key"}}}`))

	srv := &Server{
		daemon:       newSignalDaemon(hub),
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	// 1. keyA cannot receive acctB
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/"+acctB, nil)
	req.Header.Set("Authorization", "Bearer "+keyA.Key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected keyA to be forbidden from receiving acctB, got %d", rec.Code)
	}

	// 2. keyA can receive acctA, and only sees messages received AFTER keyA was created
	req = httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/"+acctA, nil)
	req.Header.Set("Authorization", "Bearer "+keyA.Key)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected keyA to receive acctA (200), got %d: %s", rec.Code, rec.Body.String())
	}
	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "before-key") || strings.Contains(bodyStr, "acctB-msg") || !strings.Contains(bodyStr, "after-key") {
		t.Errorf("Unexpected history filtering result: %s", bodyStr)
	}

	// 3. Issue 9: Argument injection via recipient starting with '-' is rejected with 400 Bad Request
	badReaction := `{"recipient":"--config=/tmp/evil","reaction":"👍","target_author":"+15550001111","timestamp":1731430000000}`
	req = httptest.NewRequest(http.MethodPost, "http://localhost:8080/v1/reactions/"+acctB, strings.NewReader(badReaction))
	req.Header.Set("Authorization", "Bearer "+keyB.Key)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected flag-like recipient '--config=/tmp/evil' to be rejected with 400, got %d", rec.Code)
	}
}

// Issue 4: /v1/qrcodelink route is removed (returns 404 Not Found; registration & linking are terminal-only)
func TestQrCodeLinkRouteRemoved(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	srv := &Server{
		hub:          newWSHub(),
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()
	adminSession := createAdminSession(t, handler, testRootKey)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "http://localhost:8080/v1/qrcodelink", nil)
		req.Header.Set("Authorization", "Bearer "+adminSession)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("Expected %s /v1/qrcodelink to return 404 Not Found, got %d", method, rec.Code)
		}
	}
}

// Issues 5, 6, 10, 12: Host, Origin, Content-Type, Body Size Limits, Login Lockout, Send Rate Limit, and Security Headers
func TestSecurityControlsAndRateLimits(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	sendKey, _ := ks.CreateKey("Sender", []string{"+15551234567"}, []string{"send", "receive"})
	hub := newWSHub()
	go hub.run()

	srv := &Server{
		daemon:       newSignalDaemon(hub),
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
		loginLimiter: newRateLimiter(3, time.Minute),
		sendLimiter:  newRateLimiter(2, time.Minute),
	}
	handler := srv.Handler()

	// 1. Issue 12: Security headers present
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("Expected Content-Security-Policy and X-Frame-Options: DENY headers, got %v", rec.Header())
	}

	// 2. Issue 5: Foreign Host header rejected
	req = httptest.NewRequest(http.MethodGet, "http://evil-rebind.com:8080/v1/health", nil)
	req.Host = "evil-rebind.com:8080"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected foreign Host header to return 403 Forbidden, got %d", rec.Code)
	}

	// 3. Issue 6: Direct root key on /api/keys without session login is rejected (401)
	req = httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/keys", nil)
	req.Header.Set("Authorization", "Bearer "+testRootKey)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected direct root key on /api/keys without session login to return 401, got %d", rec.Code)
	}

	// 4. Issue 10: Oversized body on /api/auth/login rejected with 413 Request Entity Too Large
	hugeBody := `{"admin_key":"` + strings.Repeat("A", 8192) + `"}`
	req = httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", strings.NewReader(hugeBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected oversized login body to return 413, got %d", rec.Code)
	}

	// 5. Issue 6 & Login lockout: Once a bucket reaches maxRequests (3) failed attempts,
	// the bucket is locked and rejects subsequent attempts (even with the valid root key) with 429.
	srv.loginLimiter.baseDelay = 5 * time.Millisecond
	srv.loginLimiter.maxDelay = 20 * time.Millisecond
	for i := 0; i < 3; i++ {
		badLogin := strings.NewReader(`{"admin_key":"wrong_key_attempt"}`)
		r := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", badLogin)
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "127.0.0.1:44444"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if i < 2 && w.Code != http.StatusUnauthorized {
			t.Fatalf("Expected 401 on bad login %d, got %d", i+1, w.Code)
		}
		if i == 2 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("Expected 429 on 3rd bad login attempt, got %d", w.Code)
		}
	}
	validLoginReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", strings.NewReader(`{"admin_key":"`+testRootKey+`"}`))
	validLoginReq.Header.Set("Content-Type", "application/json")
	validLoginReq.RemoteAddr = "127.0.0.1:44444"
	validLoginRec := httptest.NewRecorder()
	handler.ServeHTTP(validLoginRec, validLoginReq)
	if validLoginRec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected locked bucket to reject even valid root key with 429 Too Many Requests, got %d", validLoginRec.Code)
	}

	// 6. Issue 10: /v2/send rate limiting per account (limit=2 per minute)
	sendJSON := `{"number":"+15551234567","recipients":["+15559998888"],"message":"hello"}`
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send", strings.NewReader(sendJSON))
		r.Header.Set("Authorization", "Bearer "+sendKey.Key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		// Daemon isn't running so valid requests reach daemon.call and return 502 Bad Gateway
		if w.Code != http.StatusBadGateway {
			t.Fatalf("Expected request %d to pass rate limiter (502 from disconnected daemon), got %d", i+1, w.Code)
		}
	}
	r3 := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send", strings.NewReader(sendJSON))
	r3.Header.Set("Authorization", "Bearer "+sendKey.Key)
	r3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, r3)
	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 3rd send request to be rate-limited with 429, got %d", w3.Code)
	}
}

func TestAuthMiddlewareAllBranches(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	clientKey, _ := ks.CreateKey("TestClient", []string{"+15551234567"}, []string{"receive"})
	hub := newWSHub()
	go hub.run()

	srv := &Server{
		daemon:       newSignalDaemon(hub),
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	// 1. Blocked registration & unregistration routes return 403 Forbidden
	for _, blockedPath := range []string{"/v1/register", "/v1/unregister"} {
		req := httptest.NewRequest(http.MethodPost, "http://localhost:8080"+blockedPath, nil)
		req.Header.Set("Authorization", "Bearer "+clientKey.Key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected %s to return 403 Forbidden, got %d", blockedPath, rec.Code)
		}
	}

	// 2. X-API-Key header authentication works
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
	req.Header.Set("X-API-Key", clientKey.Key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected X-API-Key auth to succeed (200), got %d", rec.Code)
	}

	// 3. Basic Auth is not supported and is rejected with 401 Unauthorized
	req = httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
	req.SetBasicAuth("basicuser", "basicpass_strong")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected Basic Auth to be rejected with 401, got %d", rec.Code)
	}

	// 4. Admin session login and logout revocation
	// Verify /api/info requires admin auth and returns version
	unauthInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	unauthInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthInfoRec, unauthInfoReq)
	if unauthInfoRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthenticated GET /api/info to return 401, got %d", unauthInfoRec.Code)
	}

	sessToken := createAdminSession(t, handler, testRootKey)

	authInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	authInfoReq.Header.Set("Authorization", "Bearer "+sessToken)
	authInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(authInfoRec, authInfoReq)
	if authInfoRec.Code != http.StatusOK || !strings.Contains(authInfoRec.Body.String(), `"version"`) {
		t.Errorf("Expected authenticated GET /api/info to return 200 with version, got %d (%s)", authInfoRec.Code, authInfoRec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/keys", nil)
	req.Header.Set("Authorization", "Bearer "+sessToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected active session token to access /api/keys (200), got %d", rec.Code)
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+sessToken)
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("Expected logout to return 200, got %d", logoutRec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/keys", nil)
	req.Header.Set("Authorization", "Bearer "+sessToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected logged-out session token to return 401, got %d", rec.Code)
	}
}

func TestWebSocketParserFramesAndBroadcastIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	clientKey, _ := ks.CreateKey("WSParserKey", []string{"+15551234567"}, []string{"receive"})
	hub := newWSHub()
	go hub.run()

	srv := &Server{
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	connectWS := func() net.Conn {
		cConn, sConn := net.Pipe()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
		req.Header.Set("Authorization", "Bearer "+clientKey.Key)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		rec := &pipeHijackRecorder{
			ResponseRecorder: httptest.NewRecorder(),
			serverConn:       sConn,
		}
		go handler.ServeHTTP(rec, req)
		reader := bufio.NewReader(cConn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		return cConn
	}

	// 1. Masked Ping (0x89) -> Server responds with Pong (0x8A) with unmasked payload "ping"
	conn1 := connectWS()
	defer conn1.Close()

	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	plain := []byte("ping")
	maskedPing := []byte{0x89, 0x80 | byte(len(plain)), mask[0], mask[1], mask[2], mask[3]}
	for i, b := range plain {
		maskedPing = append(maskedPing, b^mask[i%4])
	}
	go func() {
		_, _ = conn1.Write(maskedPing)
	}()

	_ = conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	pongHeader := make([]byte, 2)
	if _, err := conn1.Read(pongHeader); err != nil {
		t.Fatalf("Failed reading pong header: %v", err)
	}
	if pongHeader[0] != 0x8A || pongHeader[1] != 4 {
		t.Fatalf("Expected pong header [0x8A, 4], got %v", pongHeader)
	}
	pongBody := make([]byte, 4)
	if _, err := conn1.Read(pongBody); err != nil || string(pongBody) != "ping" {
		t.Fatalf("Expected pong payload 'ping', got %q (err=%v)", string(pongBody), err)
	}

	// 2. Unmasked frame -> Server responds with Close 1002 (0x03EA)
	conn2 := connectWS()
	defer conn2.Close()
	go func() {
		_, _ = conn2.Write([]byte{0x89, 0x00}) // unmasked ping
	}()
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	closeFrame := make([]byte, 4)
	if _, err := conn2.Read(closeFrame); err != nil {
		t.Fatalf("Failed reading 1002 close frame: %v", err)
	}
	if closeFrame[0]&0x0F != 0x08 || binary.BigEndian.Uint16(closeFrame[2:4]) != 1002 {
		t.Errorf("Expected close code 1002 for unmasked frame, got %v", closeFrame)
	}

	// 3. 16-bit extended length (126 -> 200 bytes > 125 limit) -> Close 1009 (0x03F1)
	conn3 := connectWS()
	defer conn3.Close()
	go func() {
		_, _ = conn3.Write([]byte{0x81, 0x80 | 126, 0x00, 200, 0, 0, 0, 0})
	}()
	_ = conn3.SetReadDeadline(time.Now().Add(2 * time.Second))
	close1009 := make([]byte, 4)
	if _, err := conn3.Read(close1009); err != nil {
		t.Fatalf("Failed reading 1009 close frame: %v", err)
	}
	if close1009[0]&0x0F != 0x08 || binary.BigEndian.Uint16(close1009[2:4]) != 1009 {
		t.Errorf("Expected close code 1009 for 200-byte frame, got %v", close1009)
	}
}

func TestErrorSanitizationAndDaemonStopRace(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	hub := newWSHub()
	go hub.run()

	daemon := newSignalDaemon(hub)
	// Start and stop daemon concurrently under -race
	daemon.start()
	time.Sleep(10 * time.Millisecond)
	daemon.stop()

	srv := &Server{
		daemon:       daemon,
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
		profileUpdater: func(ctx context.Context, account, givenName, familyName, avatarPath string) ([]byte, error) {
			return nil, &os.PathError{Op: "exec", Path: "/home/.local/share/signal-cli/secret", Err: os.ErrPermission}
		},
	}
	handler := srv.Handler()
	// Verify /api/info requires admin auth and returns version
	unauthInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	unauthInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthInfoRec, unauthInfoReq)
	if unauthInfoRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthenticated GET /api/info to return 401, got %d", unauthInfoRec.Code)
	}

	sessToken := createAdminSession(t, handler, testRootKey)

	authInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	authInfoReq.Header.Set("Authorization", "Bearer "+sessToken)
	authInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(authInfoRec, authInfoReq)
	if authInfoRec.Code != http.StatusOK || !strings.Contains(authInfoRec.Body.String(), `"version"`) {
		t.Errorf("Expected authenticated GET /api/info to return 200 with version, got %d (%s)", authInfoRec.Code, authInfoRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/accounts/profile",
		strings.NewReader(`{"account":"+15551234567","given_name":"Alice"}`))
	req.Header.Set("Authorization", "Bearer "+sessToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("Expected 502 from failed profileUpdater, got %d", rec.Code)
	}
	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Expected valid JSON error body, got %q (err=%v)", rec.Body.String(), err)
	}
	if strings.Contains(rec.Body.String(), "/home/.local/share/signal-cli/secret") {
		t.Errorf("Expected internal file path not to leak in HTTP error body, got %s", rec.Body.String())
	}
}

func TestLegacyKeyMigrationPersistsImmediately(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "api_keys.json")

	legacySecret := "sig_legacy_plaintext_secret_key_value_12345"
	legacyJSON := `[{"id":"key_0102030405060708","name":"LegacyBot","key":"` + legacySecret + `","prefix":"sig_le...","accounts":["+15551234567"],"permissions":["send","receive"]}]`
	if err := os.WriteFile(storePath, []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("Failed to write legacy store fixture: %v", err)
	}

	ks, err := newKeyStore(storePath)
	if err != nil {
		t.Fatalf("Expected legacy store migration to succeed, got: %v", err)
	}

	// Verify key still authenticates via SHA-256 hash
	if _, ok := ks.LookupKey(legacySecret); !ok {
		t.Fatalf("Expected migrated legacy key to authenticate via LookupKey")
	}

	// Verify disk file was rewritten immediately on load without plaintext secret
	diskBytes, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("Failed reading store after migration: %v", err)
	}
	if strings.Contains(string(diskBytes), legacySecret) {
		t.Errorf("Expected migrated key store on disk to scrub plaintext key immediately on load, got: %s", string(diskBytes))
	}
	if !strings.Contains(string(diskBytes), hashSecret(legacySecret)) {
		t.Errorf("Expected migrated key store on disk to contain SHA-256 key_hash")
	}
}

func TestStrictCSPAndLogForgingProtection(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	hub := newWSHub()
	go hub.run()

	srv := &Server{
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	// 1. Verify CSP does not allow 'unsafe-inline' in script-src
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("Expected strict script-src 'self' without 'unsafe-inline', got CSP: %s", csp)
	}

	// 2. Verify /api/keys/<id> rejects malformed/newline-injected key IDs with 400 Bad Request
	// Verify /api/info requires admin auth and returns version
	unauthInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	unauthInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthInfoRec, unauthInfoReq)
	if unauthInfoRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthenticated GET /api/info to return 401, got %d", unauthInfoRec.Code)
	}

	sessToken := createAdminSession(t, handler, testRootKey)

	authInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	authInfoReq.Header.Set("Authorization", "Bearer "+sessToken)
	authInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(authInfoRec, authInfoReq)
	if authInfoRec.Code != http.StatusOK || !strings.Contains(authInfoRec.Body.String(), `"version"`) {
		t.Errorf("Expected authenticated GET /api/info to return 200 with version, got %d (%s)", authInfoRec.Code, authInfoRec.Body.String())
	}
	forgedReq := httptest.NewRequest(http.MethodDelete, "http://localhost:8080/api/keys/key_bad%0Aforged-log-line", nil)
	forgedReq.Header.Set("Authorization", "Bearer "+sessToken)
	forgedRec := httptest.NewRecorder()
	handler.ServeHTTP(forgedRec, forgedReq)
	if forgedRec.Code != http.StatusBadRequest {
		t.Errorf("Expected malformed/newline key ID to return 400 Bad Request, got %d", forgedRec.Code)
	}
}

func TestBuildRegisterRPCRequestFromStdin(t *testing.T) {
	rk := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	payload, err := buildRegisterRPCRequest("my-account-id", strings.NewReader(rk+"\n"), []string{"--reregister", "--captcha=signal-hcaptcha.test"})
	if err != nil {
		t.Fatalf("Expected buildRegisterRPCRequest to succeed, got: %v", err)
	}

	var rpcReq struct {
		JSONRPC string                 `json:"jsonrpc"`
		Method  string                 `json:"method"`
		Params  map[string]interface{} `json:"params"`
		ID      int64                  `json:"id"`
	}
	if err := json.Unmarshal(payload, &rpcReq); err != nil {
		t.Fatalf("Failed to unmarshal JSON-RPC register payload: %v", err)
	}
	if rpcReq.Method != "register" || rpcReq.Params["account"] != "my-account-id" || rpcReq.Params["recoveryKey"] != rk || rpcReq.Params["reregister"] != true {
		t.Errorf("Unexpected JSON-RPC register payload: %+v", rpcReq)
	}

	// Reject empty stdin recovery key
	if _, err := buildRegisterRPCRequest("my-account-id", strings.NewReader("   \n"), nil); err == nil {
		t.Errorf("Expected empty recovery key on stdin to fail")
	}

	// Reject unsupported or --recovery-key CLI flags
	if _, err := buildRegisterRPCRequest("my-account-id", strings.NewReader(rk), []string{"--recovery-key", rk}); err == nil {
		t.Errorf("Expected --recovery-key CLI flag to be rejected")
	}

	// Verify parseRegisterRPCResponse returns an error when no matching ID == 1 response arrives
	if err := parseRegisterRPCResponse(strings.NewReader("")); err == nil {
		t.Errorf("Expected empty RPC output to return an error instead of nil")
	}
	if err := parseRegisterRPCResponse(strings.NewReader(`{"jsonrpc":"2.0","method":"receive","params":{}}` + "\n")); err == nil {
		t.Errorf("Expected RPC stream without ID=1 response to return an error")
	}
	if err := parseRegisterRPCResponse(strings.NewReader(`{"jsonrpc":"2.0","error":{"code":-1,"message":"bad key"},"id":1}` + "\n")); err == nil {
		t.Errorf("Expected RPC error response to return an error")
	}
	if err := parseRegisterRPCResponse(strings.NewReader(`{"jsonrpc":"2.0","result":{},"id":1}` + "\n")); err != nil {
		t.Errorf("Expected matching ID=1 success response to return nil, got: %v", err)
	}

	// Verify CLI fallback flag builder
	cliArgs, err := buildRegisterCLIFlags("B2E90D33-418B-45A0-8C41-CB2D55E05CA4", rk, []string{"--reregister"})
	if err != nil {
		t.Fatalf("buildRegisterCLIFlags failed: %v", err)
	}
	expectedPrefix := []string{"--config", configDir, "-a", "B2E90D33-418B-45A0-8C41-CB2D55E05CA4", "register", "--recovery-key", rk, "--reregister"}
	if len(cliArgs) != len(expectedPrefix) {
		t.Fatalf("Unexpected cliArgs length: got %v, want %v", cliArgs, expectedPrefix)
	}
	for i := range expectedPrefix {
		if cliArgs[i] != expectedPrefix[i] {
			t.Errorf("cliArgs[%d] = %q, want %q", i, cliArgs[i], expectedPrefix[i])
		}
	}
}

func TestWebSocketConnectionLimitsAndPongLiveness(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	key1, _ := ks.CreateKey("Key1", []string{"+15551234567"}, []string{"receive"})
	key2, _ := ks.CreateKey("Key2", []string{"+15551234567"}, []string{"receive"})

	hub := newWSHub()
	hub.maxPerKey = 2
	hub.maxTotal = 3
	hub.pingInterval = 25 * time.Millisecond
	hub.pongWait = 80 * time.Millisecond
	go hub.run()

	srv := &Server{
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	openWS := func(token string) (net.Conn, *pipeHijackRecorder) {
		cConn, sConn := net.Pipe()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		rec := &pipeHijackRecorder{
			ResponseRecorder: httptest.NewRecorder(),
			serverConn:       sConn,
		}
		done := make(chan struct{})
		go func() {
			handler.ServeHTTP(rec, req)
			if !rec.hijacked {
				_ = sConn.Close()
			}
			close(done)
		}()

		_ = cConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		reader := bufio.NewReader(cConn)
		line, err := reader.ReadString('\n')
		if err != nil {
			<-done
			_ = cConn.Close()
			_ = sConn.Close()
			return nil, rec
		}
		if !strings.Contains(line, "101 Switching Protocols") {
			<-done
			_ = cConn.Close()
			_ = sConn.Close()
			return nil, rec
		}
		for {
			hdr, err := reader.ReadString('\n')
			if err != nil || hdr == "\r\n" {
				break
			}
		}
		_ = cConn.SetReadDeadline(time.Time{})
		return cConn, rec
	}

	// 1. Open 2 connections with key1 (succeeds up to maxPerKey=2)
	c1, _ := openWS(key1.Key)
	if c1 == nil {
		t.Fatalf("Expected 1st connection for key1 to succeed")
	}
	defer c1.Close()

	c2, _ := openWS(key1.Key)
	if c2 == nil {
		t.Fatalf("Expected 2nd connection for key1 to succeed")
	}
	defer c2.Close()

	// 2. 3rd connection with key1 is rejected with 429 Too Many Requests (per-key limit)
	c3, rec3 := openWS(key1.Key)
	if c3 != nil || rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 3rd connection for key1 to fail with 429, got conn=%v status=%d", c3, rec3.Code)
	}

	// 3. 1st connection with key2 succeeds (total=3 == maxTotal)
	c4, _ := openWS(key2.Key)
	if c4 == nil {
		t.Fatalf("Expected 1st connection for key2 to succeed (reaching maxTotal=3)")
	}
	defer c4.Close()

	// 4. 2nd connection with key2 is rejected with 429 Too Many Requests (global maxTotal=3 reached)
	c5, rec5 := openWS(key2.Key)
	if c5 != nil || rec5.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 4th total connection to fail with 429, got conn=%v status=%d", c5, rec5.Code)
	}

	// 5. Keep c1 alive by answering Pings with masked Pongs, while c2 and c4 stay silent and time out
	stopPong := make(chan struct{})
	defer close(stopPong)
	go func() {
		buf := make([]byte, 16)
		for {
			select {
			case <-stopPong:
				return
			default:
			}
			_ = c1.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
			n, err := c1.Read(buf)
			if err != nil {
				continue
			}
			if n >= 2 && (buf[0]&0x0F) == 0x09 {
				// Reply with masked empty Pong (0x8A, 0x80, 4-byte mask)
				_, _ = c1.Write([]byte{0x8A, 0x80, 0x11, 0x22, 0x33, 0x44})
			}
		}
	}()

	// Wait past pongWait (80ms) so silent connections c2 and c4 are closed by their read deadline
	time.Sleep(160 * time.Millisecond)

	if got := hub.ClientCount(); got != 1 {
		t.Errorf("Expected only the pong-answering connection to remain open (count=1), got %d", got)
	}
}

func TestWebSocketAdminSessionClosedOnLogoutAndExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	hub := newWSHub()
	go hub.run()

	sessStore := newSessionStore(90 * time.Millisecond)
	srv := &Server{
		hub:          hub,
		keyStore:     ks,
		sessionStore: sessStore,
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	openSessionWS := func(sessionToken string) net.Conn {
		cConn, sConn := net.Pipe()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
		req.Header.Set("Authorization", "Bearer "+sessionToken)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		rec := &pipeHijackRecorder{
			ResponseRecorder: httptest.NewRecorder(),
			serverConn:       sConn,
		}
		go handler.ServeHTTP(rec, req)

		reader := bufio.NewReader(cConn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		// Drain incoming frames in background so writes on net.Pipe don't block
		go func() {
			buf := make([]byte, 256)
			for {
				if _, err := cConn.Read(buf); err != nil {
					return
				}
			}
		}()
		return cConn
	}

	// 1. WebSocket opened by an admin session is closed immediately on /api/auth/logout
	sess1 := createAdminSession(t, handler, testRootKey)
	ws1 := openSessionWS(sess1)
	defer ws1.Close()

	time.Sleep(15 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Fatalf("Expected 1 active session WebSocket before logout, got %d", hub.ClientCount())
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+sess1)
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on logout, got %d", logoutRec.Code)
	}

	if hub.ClientCount() != 0 {
		t.Errorf("Expected session WebSocket to be closed immediately on logout, got count=%d", hub.ClientCount())
	}

	// 2. WebSocket opened by an admin session is closed automatically when the session expires
	sess2 := createAdminSession(t, handler, testRootKey)
	ws2 := openSessionWS(sess2)
	defer ws2.Close()

	time.Sleep(15 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Fatalf("Expected 1 active session WebSocket before expiry, got %d", hub.ClientCount())
	}

	// Wait for 90ms session TTL + sweeper tick to expire sess2
	time.Sleep(150 * time.Millisecond)

	if hub.ClientCount() != 0 {
		t.Errorf("Expected session WebSocket to be closed automatically after session expiry, got count=%d", hub.ClientCount())
	}
}

func TestLoginThrottleSweepAndTrustedProxy(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	hub := newWSHub()
	go hub.run()

	// Default: trust NO proxy IPs when TRUSTED_PROXIES is empty (even for 127.0.0.1 or RFC1918 private IPs)
	untrustedSrv := &Server{
		trustedProxyHeader: "X-Forwarded-For",
		trustedProxies:     parseTrustedProxies(""),
	}
	if untrustedSrv.isTrustedProxyIP("127.0.0.1") || untrustedSrv.isTrustedProxyIP("10.0.0.5") || untrustedSrv.isTrustedProxyIP("192.168.1.10") {
		t.Fatalf("Expected default empty TRUSTED_PROXIES to trust no IPs")
	}
	spoofReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", nil)
	spoofReq.RemoteAddr = "10.0.0.5:50000"
	spoofReq.Header.Set("X-Forwarded-For", "198.51.100.99")
	if gotIP := untrustedSrv.realClientIP(spoofReq); gotIP != "10.0.0.5" {
		t.Fatalf("Expected untrusted private peer 10.0.0.5 not to spoof X-Forwarded-For when TRUSTED_PROXIES is unset, got %s", gotIP)
	}

	limiter := newRateLimiter(3, 80*time.Millisecond)
	limiter.baseDelay = 5 * time.Millisecond
	limiter.maxDelay = 25 * time.Millisecond

	srv := &Server{
		hub:                hub,
		keyStore:           ks,
		sessionStore:       newSessionStore(time.Minute),
		apiKeyMgmt:         testRootKey,
		loginLimiter:       limiter,
		trustedProxyHeader: "X-Forwarded-For",
		trustedProxies:     parseTrustedProxies("127.0.0.1/32"),
	}
	handler := srv.Handler()

	// 1. Atomic check-and-record under parallel bad guesses: out of 6 concurrent bad guesses from 203.0.113.10,
	// only 2 return 401 and the remaining 4 return 429 (none slip past maxRequests=3)
	var wg sync.WaitGroup
	var count401, count429 atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", strings.NewReader(`{"admin_key":"wrong_parallel_guess"}`))
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "127.0.0.1:50000"
			r.Header.Set("X-Forwarded-For", "203.0.113.10")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			switch w.Code {
			case http.StatusUnauthorized:
				count401.Add(1)
			case http.StatusTooManyRequests:
				count429.Add(1)
			}
		}()
	}
	wg.Wait()

	if count401.Load() != 2 || count429.Load() != 4 {
		t.Errorf("Expected atomic parallel failure counting (2x 401, 4x 429), got 401=%d 429=%d", count401.Load(), count429.Load())
	}

	// Verify failure slice per IP is strictly capped at maxRequests (3) even after excess ThrottleFailure calls
	for i := 0; i < 50; i++ {
		limiter.ThrottleFailure("203.0.113.10")
	}
	limiter.mu.Lock()
	cappedLen := len(limiter.events["203.0.113.10"])
	limiter.mu.Unlock()
	if cappedLen != 3 {
		t.Errorf("Expected failure history slice to be capped at maxRequests=3, got len=%d", cappedLen)
	}

	// 2. Different client IP behind the same reverse proxy (203.0.113.99) has its own bucket
	rOther := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", strings.NewReader(`{"admin_key":"wrong_once"}`))
	rOther.Header.Set("Content-Type", "application/json")
	rOther.RemoteAddr = "127.0.0.1:50000"
	rOther.Header.Set("X-Forwarded-For", "203.0.113.99")
	wOther := httptest.NewRecorder()
	handler.ServeHTTP(wOther, rOther)
	if wOther.Code != http.StatusUnauthorized {
		t.Errorf("Expected first failure from distinct X-Forwarded-For IP to return 401, got %d", wOther.Code)
	}

	// 3. Sweeper evicts expired buckets after the 80ms window
	if limiter.BucketCount() == 0 {
		t.Fatalf("Expected active buckets in limiter before sweep")
	}
	time.Sleep(150 * time.Millisecond)
	if got := limiter.BucketCount(); got != 0 {
		t.Errorf("Expected RateLimiter sweeper to evict expired buckets, got %d remaining", got)
	}
}

func TestOriginSchemeAndPortValidation(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	clientKey, _ := ks.CreateKey("OriginClient", []string{"+15551234567"}, []string{"send", "receive"})
	hub := newWSHub()
	go hub.run()

	srv := &Server{
		daemon:       newSignalDaemon(hub),
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
		allowedHosts: defaultAllowedHosts("signal.example.com"),
	}
	handler := srv.Handler()

	sendBody := `{"number":"+15551234567","recipients":["+15559998888"],"message":"test"}`

	// 1. Foreign port on same host (Origin: http://localhost:9999 -> Host: localhost:8080) is rejected on POST /v2/send
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send", strings.NewReader(sendBody))
	req.Header.Set("Authorization", "Bearer "+clientKey.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:9999")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected Origin http://localhost:9999 on POST /v2/send to return 403 Forbidden, got %d", rec.Code)
	}

	// 2. Foreign port on same host (Origin: http://localhost:9999 -> Host: localhost:8080) is rejected on WebSocket upgrade
	wsReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
	wsReq.Header.Set("Authorization", "Bearer "+clientKey.Key)
	wsReq.Header.Set("Upgrade", "websocket")
	wsReq.Header.Set("Connection", "Upgrade")
	wsReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	wsReq.Header.Set("Origin", "http://localhost:9999")
	wsRec := httptest.NewRecorder()
	handler.ServeHTTP(wsRec, wsReq)
	if wsRec.Code != http.StatusForbidden {
		t.Errorf("Expected Origin http://localhost:9999 on WebSocket upgrade to return 403 Forbidden, got %d", wsRec.Code)
	}

	// 3. Mismatched scheme (Origin: https://localhost:8080 on plain HTTP request) is rejected
	reqScheme := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send", strings.NewReader(sendBody))
	reqScheme.Header.Set("Authorization", "Bearer "+clientKey.Key)
	reqScheme.Header.Set("Content-Type", "application/json")
	reqScheme.Header.Set("Origin", "https://localhost:8080")
	recScheme := httptest.NewRecorder()
	handler.ServeHTTP(recScheme, reqScheme)
	if recScheme.Code != http.StatusForbidden {
		t.Errorf("Expected mismatched scheme Origin https://localhost:8080 on HTTP request to return 403, got %d", recScheme.Code)
	}

	// 4. Exact matching scheme, host, and port (Origin: http://localhost:8080) passes Origin check (reaches daemon -> 502)
	reqOK := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send", strings.NewReader(sendBody))
	reqOK.Header.Set("Authorization", "Bearer "+clientKey.Key)
	reqOK.Header.Set("Content-Type", "application/json")
	reqOK.Header.Set("Origin", "http://localhost:8080")
	recOK := httptest.NewRecorder()
	handler.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusBadGateway {
		t.Errorf("Expected exact same-origin http://localhost:8080 to pass Origin check (502), got %d", recOK.Code)
	}

	// 5. Reverse proxy TLS termination (X-Forwarded-Proto: https, Host: signal.example.com):
	// Without TRUSTED_PROXIES configured, X-Forwarded-Proto from 127.0.0.1 is NOT trusted (https Origin rejected on plain HTTP).
	proxyUntrusted := httptest.NewRequest(http.MethodPost, "http://signal.example.com/v2/send", strings.NewReader(sendBody))
	proxyUntrusted.Host = "signal.example.com"
	proxyUntrusted.RemoteAddr = "127.0.0.1:40000"
	proxyUntrusted.Header.Set("X-Forwarded-Proto", "https")
	proxyUntrusted.Header.Set("Authorization", "Bearer "+clientKey.Key)
	proxyUntrusted.Header.Set("Content-Type", "application/json")
	proxyUntrusted.Header.Set("Origin", "https://signal.example.com")
	proxyUntrustedRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyUntrustedRec, proxyUntrusted)
	if proxyUntrustedRec.Code != http.StatusForbidden {
		t.Errorf("Expected X-Forwarded-Proto to be ignored when TRUSTED_PROXIES is unset (403), got %d", proxyUntrustedRec.Code)
	}

	// Once TRUSTED_PROXIES explicitly includes 127.0.0.1/32, allows Origin: https://signal.example.com and rejects Origin: http://signal.example.com
	srv.trustedProxies = parseTrustedProxies("127.0.0.1/32")
	proxyOK := httptest.NewRequest(http.MethodPost, "http://signal.example.com/v2/send", strings.NewReader(sendBody))
	proxyOK.Host = "signal.example.com"
	proxyOK.RemoteAddr = "127.0.0.1:40000"
	proxyOK.Header.Set("X-Forwarded-Proto", "https")
	proxyOK.Header.Set("Authorization", "Bearer "+clientKey.Key)
	proxyOK.Header.Set("Content-Type", "application/json")
	proxyOK.Header.Set("Origin", "https://signal.example.com")
	proxyOKRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyOKRec, proxyOK)
	if proxyOKRec.Code != http.StatusBadGateway {
		t.Errorf("Expected https Origin behind trusted TLS reverse proxy to pass Origin check (502), got %d", proxyOKRec.Code)
	}

	proxyBadScheme := httptest.NewRequest(http.MethodPost, "http://signal.example.com/v2/send", strings.NewReader(sendBody))
	proxyBadScheme.Host = "signal.example.com"
	proxyBadScheme.RemoteAddr = "127.0.0.1:40000"
	proxyBadScheme.Header.Set("X-Forwarded-Proto", "https")
	proxyBadScheme.Header.Set("Authorization", "Bearer "+clientKey.Key)
	proxyBadScheme.Header.Set("Content-Type", "application/json")
	proxyBadScheme.Header.Set("Origin", "http://signal.example.com")
	proxyBadRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyBadRec, proxyBadScheme)
	if proxyBadRec.Code != http.StatusForbidden {
		t.Errorf("Expected downgrade http Origin behind https reverse proxy to return 403, got %d", proxyBadRec.Code)
	}
}

func TestAdminUIAndUpdateProfileEndpoint(t *testing.T) {
	// 1. Verify buildUpdateProfileParams maps to signal-cli JSON-RPC updateProfile parameters
	params := buildUpdateProfileParams("+15551234567", "Alice", "Smith", "/tmp/signal-avatar-123.png")
	if params["account"] != "+15551234567" || params["givenName"] != "Alice" || params["familyName"] != "Smith" || params["avatar"] != "/tmp/signal-avatar-123.png" {
		t.Fatalf("Unexpected buildUpdateProfileParams with all fields: got %+v", params)
	}

	paramsOptionalOmitted := buildUpdateProfileParams("+15551234567", "Alice", "", "")
	if paramsOptionalOmitted["account"] != "+15551234567" || paramsOptionalOmitted["givenName"] != "Alice" || paramsOptionalOmitted["familyName"] != nil || paramsOptionalOmitted["avatar"] != nil {
		t.Fatalf("Unexpected buildUpdateProfileParams with optional fields omitted: got %+v", paramsOptionalOmitted)
	}

	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	nonAdminKey, _ := ks.CreateKey("NonAdmin", []string{"+15551234567"}, []string{"send", "receive"})

	hub := newWSHub()
	go hub.run()
	daemon := newSignalDaemon(hub)
	clientConn, daemonConn := net.Pipe()
	defer clientConn.Close()
	defer daemonConn.Close()

	daemon.mu.Lock()
	daemon.conn = clientConn
	daemon.mu.Unlock()
	go daemon.readLoop(clientConn)

	var capturedMethod, capturedAccount, capturedGiven, capturedFamily, capturedAvatarPath string
	var capturedAvatarBytes []byte
	var rpcMu sync.Mutex

	// Mock signal-cli JSON-RPC daemon handling updateProfile
	go func() {
		scanner := bufio.NewScanner(daemonConn)
		for scanner.Scan() {
			var req struct {
				JSONRPC string                 `json:"jsonrpc"`
				Method  string                 `json:"method"`
				Params  map[string]interface{} `json:"params"`
				ID      int64                  `json:"id"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
				continue
			}
			rpcMu.Lock()
			capturedMethod = req.Method
			capturedAccount, _ = req.Params["account"].(string)
			capturedGiven, _ = req.Params["givenName"].(string)
			capturedFamily, _ = req.Params["familyName"].(string)
			capturedAvatarPath, _ = req.Params["avatar"].(string)
			if capturedAvatarPath != "" {
				capturedAvatarBytes, _ = os.ReadFile(capturedAvatarPath)
			}
			rpcMu.Unlock()

			resp := `{"jsonrpc":"2.0","result":{},"id":` + strconvFormatInt(req.ID) + `}` + "\n"
			_, _ = daemonConn.Write([]byte(resp))
		}
	}()

	srv := &Server{
		daemon:       daemon,
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	// 2. Verify /admin serves admin.html and /keys redirects to /admin
	adminPageReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin", nil)
	adminPageRec := httptest.NewRecorder()
	handler.ServeHTTP(adminPageRec, adminPageReq)
	if adminPageRec.Code != http.StatusOK || !strings.Contains(adminPageRec.Body.String(), "Account Profile") {
		t.Fatalf("Expected GET /admin to return 200 with Account Profile UI, got %d", adminPageRec.Code)
	}

	keysRedirectReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/keys", nil)
	keysRedirectRec := httptest.NewRecorder()
	handler.ServeHTTP(keysRedirectRec, keysRedirectReq)
	if keysRedirectRec.Code != http.StatusMovedPermanently || keysRedirectRec.Header().Get("Location") != "/admin" {
		t.Errorf("Expected GET /keys to redirect 301 to /admin, got %d (Location: %s)", keysRedirectRec.Code, keysRedirectRec.Header().Get("Location"))
	}

	// 3. Reject unauthenticated or non-admin key attempts on /api/accounts/profile
	unauthProfileReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/accounts/profile",
		strings.NewReader(`{"account":"+15551234567","given_name":"Alice"}`))
	unauthProfileReq.Header.Set("Authorization", "Bearer "+nonAdminKey.Key)
	unauthProfileReq.Header.Set("Content-Type", "application/json")
	unauthProfileRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthProfileRec, unauthProfileReq)
	if unauthProfileRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected non-admin key on /api/accounts/profile to return 401, got %d", unauthProfileRec.Code)
	}

	// Verify /api/info requires admin auth and returns version
	unauthInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	unauthInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthInfoRec, unauthInfoReq)
	if unauthInfoRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthenticated GET /api/info to return 401, got %d", unauthInfoRec.Code)
	}

	sessToken := createAdminSession(t, handler, testRootKey)

	authInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	authInfoReq.Header.Set("Authorization", "Bearer "+sessToken)
	authInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(authInfoRec, authInfoReq)
	if authInfoRec.Code != http.StatusOK || !strings.Contains(authInfoRec.Body.String(), `"version"`) {
		t.Errorf("Expected authenticated GET /api/info to return 200 with version, got %d (%s)", authInfoRec.Code, authInfoRec.Body.String())
	}

	// 4. Reject flag injection in given_name or family_name
	flagInjectReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/accounts/profile",
		strings.NewReader(`{"account":"+15551234567","given_name":"--avatar=/etc/passwd"}`))
	flagInjectReq.Header.Set("Authorization", "Bearer "+sessToken)
	flagInjectReq.Header.Set("Content-Type", "application/json")
	flagInjectRec := httptest.NewRecorder()
	handler.ServeHTTP(flagInjectRec, flagInjectReq)
	if flagInjectRec.Code != http.StatusBadRequest {
		t.Errorf("Expected flag-injected given_name to return 400, got %d", flagInjectRec.Code)
	}

	// 5. Reject non-image avatar payload AND malformed image with a valid PNG header
	badImgReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/accounts/profile",
		strings.NewReader(`{"account":"+15551234567","given_name":"Alice","avatar":"data:text/plain;base64,aGVsbG8gd29ybGQ="}`))
	badImgReq.Header.Set("Authorization", "Bearer "+sessToken)
	badImgReq.Header.Set("Content-Type", "application/json")
	badImgRec := httptest.NewRecorder()
	handler.ServeHTTP(badImgRec, badImgReq)
	if badImgRec.Code != http.StatusBadRequest {
		t.Errorf("Expected non-image avatar payload to return 400, got %d", badImgRec.Code)
	}

	// Valid 8-byte PNG signature (\x89PNG\r\n\x1a\n) followed by corrupt bytes ("corrupt!") -> base64 "iVBORw0KGgpjb3JydXB0IQ=="
	corruptPNGReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/accounts/profile",
		strings.NewReader(`{"account":"+15551234567","given_name":"Alice","avatar":"data:image/png;base64,iVBORw0KGgpjb3JydXB0IQ=="}`))
	corruptPNGReq.Header.Set("Authorization", "Bearer "+sessToken)
	corruptPNGReq.Header.Set("Content-Type", "application/json")
	corruptPNGRec := httptest.NewRecorder()
	handler.ServeHTTP(corruptPNGRec, corruptPNGReq)
	if corruptPNGRec.Code != http.StatusBadRequest {
		t.Errorf("Expected corrupt PNG with valid magic header to be rejected by image.Decode (400), got %d", corruptPNGRec.Code)
	}

	// Reject oversized avatar dimensions (> 1024x1024) at DecodeConfig before allocating pixel buffers
	oversizedGIF := []byte{'G', 'I', 'F', '8', '9', 'a', 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00} // 2048x2048 GIF header
	if _, _, dimErr := sanitizeAvatarBytes(oversizedGIF); dimErr == nil || !strings.Contains(dimErr.Error(), "1024x1024") {
		t.Errorf("Expected 2048x2048 avatar header to be rejected with 1024x1024 limit error, got %v", dimErr)
	}

	// 6. Valid profile update via s.daemon.call("updateProfile", ...) with First Name, Last Name, and re-encoded 1x1 PNG Avatar
	const valid1x1PNGBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
	profileBody := `{"account":"+15551234567","given_name":"Alice","family_name":"Smith","avatar":"data:image/png;base64,` + valid1x1PNGBase64 + `"}`
	validProfileReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/accounts/profile", strings.NewReader(profileBody))
	validProfileReq.Header.Set("Authorization", "Bearer "+sessToken)
	validProfileReq.Header.Set("Content-Type", "application/json")
	validProfileRec := httptest.NewRecorder()
	handler.ServeHTTP(validProfileRec, validProfileReq)
	if validProfileRec.Code != http.StatusOK {
		t.Fatalf("Expected valid profile update to return 200, got %d (%s)", validProfileRec.Code, validProfileRec.Body.String())
	}

	rpcMu.Lock()
	if capturedMethod != "updateProfile" || capturedAccount != "+15551234567" || capturedGiven != "Alice" || capturedFamily != "Smith" {
		t.Errorf("Unexpected captured RPC updateProfile fields: method=%q account=%q given=%q family=%q", capturedMethod, capturedAccount, capturedGiven, capturedFamily)
	}
	if !strings.HasSuffix(capturedAvatarPath, ".png") || len(capturedAvatarBytes) == 0 {
		t.Errorf("Expected temporary .png avatar file with re-encoded PNG bytes, got path=%q len=%d", capturedAvatarPath, len(capturedAvatarBytes))
	}
	avatarPathToCheck := capturedAvatarPath
	rpcMu.Unlock()

	// Verify temporary avatar file was cleaned up immediately after handleUpdateProfile returned
	if _, statErr := os.Stat(avatarPathToCheck); !os.IsNotExist(statErr) {
		t.Errorf("Expected temporary avatar file %q to be removed after request, statErr=%v", avatarPathToCheck, statErr)
	}
}

func TestKeyLastUsedAndExpiryAndDaemonLogSuppression(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "api_keys.json")
	ks, err := newKeyStore(storePath)
	if err != nil {
		t.Fatal(err)
	}

	hub := newWSHub()
	hub.pingInterval = 25 * time.Millisecond
	go hub.run()

	srv := &Server{
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()
	// Verify /api/info requires admin auth and returns version
	unauthInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	unauthInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthInfoRec, unauthInfoReq)
	if unauthInfoRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthenticated GET /api/info to return 401, got %d", unauthInfoRec.Code)
	}

	sessToken := createAdminSession(t, handler, testRootKey)

	authInfoReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/info", nil)
	authInfoReq.Header.Set("Authorization", "Bearer "+sessToken)
	authInfoRec := httptest.NewRecorder()
	handler.ServeHTTP(authInfoRec, authInfoReq)
	if authInfoRec.Code != http.StatusOK || !strings.Contains(authInfoRec.Body.String(), `"version"`) {
		t.Errorf("Expected authenticated GET /api/info to return 200 with version, got %d (%s)", authInfoRec.Code, authInfoRec.Body.String())
	}

	// 1. Create a key via POST /api/keys with expires_in_days=30
	createReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/keys",
		strings.NewReader(`{"name":"TrackedService","accounts":["+15551234567"],"permissions":["receive"],"expires_in_days":30}`))
	createReq.Header.Set("Authorization", "Bearer "+sessToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created from POST /api/keys, got %d (%s)", createRec.Code, createRec.Body.String())
	}
	var created APIKey
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.LastUsedAt != nil {
		t.Errorf("Expected newly created key to have nil last_used_at before first use, got %v", created.LastUsedAt)
	}
	if created.ExpiresAt == nil {
		t.Errorf("Expected expires_in_days=30 to set expires_at on created key")
	}

	// 2. Use the key to authenticate a request; verify last_used_at is recorded in memory and flushed by FlushLastUsed
	useReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
	useReq.Header.Set("Authorization", "Bearer "+created.Key)
	useRec := httptest.NewRecorder()
	handler.ServeHTTP(useRec, useReq)
	if useRec.Code != http.StatusOK {
		t.Fatalf("Expected key to authenticate GET /v1/receive/+15551234567 (200), got %d", useRec.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/keys", nil)
	listReq.Header.Set("Authorization", "Bearer "+sessToken)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from GET /api/keys, got %d", listRec.Code)
	}
	var listed []APIKey
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].LastUsedAt == nil || listed[0].ExpiresAt == nil {
		t.Fatalf("Expected GET /api/keys to include populated last_used_at and expires_at, got %+v", listed)
	}

	// Trigger background flush and verify last_used_at persists across reload
	if err := ks.FlushLastUsed(); err != nil {
		t.Fatalf("FlushLastUsed failed: %v", err)
	}
	ksReloaded, err := newKeyStore(storePath)
	if err != nil {
		t.Fatalf("Failed reloading keystore after FlushLastUsed: %v", err)
	}
	reloadedKeys := ksReloaded.ListKeys()
	if len(reloadedKeys) != 1 || reloadedKeys[0].LastUsedAt == nil {
		t.Errorf("Expected flushed last_used_at to persist across keystore reload, got %+v", reloadedKeys)
	}

	// 3. Open WebSocket with a short-lived key; verify the open socket is closed once the key expires
	shortExp := time.Now().UTC().Add(60 * time.Millisecond)
	expKey, err := ks.CreateKeyWithExpiry("ShortLived", []string{"+15551234567"}, []string{"receive"}, &shortExp)
	if err != nil {
		t.Fatalf("Failed creating short-lived key: %v", err)
	}

	cConn, sConn := net.Pipe()
	defer cConn.Close()
	wsReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
	wsReq.Header.Set("Authorization", "Bearer "+expKey.Key)
	wsReq.Header.Set("Upgrade", "websocket")
	wsReq.Header.Set("Connection", "Upgrade")
	wsReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	wsRec := &pipeHijackRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		serverConn:       sConn,
	}
	go handler.ServeHTTP(wsRec, wsReq)
	reader := bufio.NewReader(cConn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := cConn.Read(buf); err != nil {
				return
			}
		}
	}()

	time.Sleep(15 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Fatalf("Expected 1 active WebSocket before key expiry, got %d", hub.ClientCount())
	}

	// Wait past key expiry (60ms) + hub ping tick (25ms)
	time.Sleep(100 * time.Millisecond)
	if hub.ClientCount() != 0 {
		t.Errorf("Expected open WebSocket to be closed automatically after key expiry, got count=%d", hub.ClientCount())
	}

	// Subsequent HTTP requests with the expired key are also rejected
	expReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive/+15551234567", nil)
	expReq.Header.Set("Authorization", "Bearer "+expKey.Key)
	expRec := httptest.NewRecorder()
	handler.ServeHTTP(expRec, expReq)
	if expRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected expired key to be rejected with 401 Unauthorized, got %d", expRec.Code)
	}

	// 4. Verify buildDaemonCommand passes --no-receive-stdout and discards stdout/stderr by default
	cmd := buildDaemonCommand()
	joinedArgs := strings.Join(cmd.Args, " ")
	if !strings.Contains(joinedArgs, "--no-receive-stdout") {
		t.Errorf("Expected signal-cli daemon args to include --no-receive-stdout, got %v", cmd.Args)
	}
	if cmd.Stdout == os.Stdout || cmd.Stderr == os.Stderr {
		t.Errorf("Expected signal-cli daemon stdout/stderr to be discarded by default, got stdout=%v stderr=%v", cmd.Stdout, cmd.Stderr)
	}

	// 5. Concurrent CreateKey, RevokeKey, LookupKey, and FlushLastUsed must never deadlock or resurrect a revoked key
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				k, err := ks.CreateKey("ConcurrentKey", []string{"+15551234567"}, []string{"receive"})
				if err != nil {
					t.Errorf("CreateKey failed: %v", err)
					return
				}
				_, _ = ks.LookupKey(k.Key)
				_ = ks.FlushLastUsed()
				_, _ = ks.RevokeKey(k.ID)
				_ = ks.FlushLastUsed()
			}
		}()
	}
	wg.Wait()
}

func TestSendAndReactionGroupVsUsernameRouting(t *testing.T) {
	tmpDir := t.TempDir()
	ks, _ := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	sendKey, _ := ks.CreateKey("Sender", []string{"+15551234567"}, []string{"send", "receive"})
	hub := newWSHub()
	go hub.run()

	daemon := newSignalDaemon(hub)
	clientConn, daemonConn := net.Pipe()
	defer clientConn.Close()
	defer daemonConn.Close()

	daemon.mu.Lock()
	daemon.conn = clientConn
	daemon.mu.Unlock()
	go daemon.readLoop(clientConn)

	var lastMethod string
	var lastParams map[string]interface{}
	var rpcMu sync.Mutex

	// Mock signal-cli JSON-RPC server over net.Pipe
	go func() {
		scanner := bufio.NewScanner(daemonConn)
		for scanner.Scan() {
			var req struct {
				JSONRPC string                 `json:"jsonrpc"`
				Method  string                 `json:"method"`
				Params  map[string]interface{} `json:"params"`
				ID      int64                  `json:"id"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
				continue
			}
			rpcMu.Lock()
			lastMethod = req.Method
			lastParams = req.Params
			rpcMu.Unlock()

			resp := `{"jsonrpc":"2.0","result":{"timestamp":1731430000000},"id":` + strconvFormatInt(req.ID) + `}` + "\n"
			_, _ = daemonConn.Write([]byte(resp))
		}
	}()

	srv := &Server{
		daemon:       daemon,
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	// 1. /v2/send with group ID passes params["groupId"] (without "group." prefix) and NOT params["recipient"]
	sendGroupReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send",
		strings.NewReader(`{"number":"+15551234567","recipients":["group.YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="],"message":"hello group"}`))
	sendGroupReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	sendGroupReq.Header.Set("Content-Type", "application/json")
	sendGroupRec := httptest.NewRecorder()
	handler.ServeHTTP(sendGroupRec, sendGroupReq)
	if sendGroupRec.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created for group send, got %d (%s)", sendGroupRec.Code, sendGroupRec.Body.String())
	}
	rpcMu.Lock()
	if lastMethod != "send" || lastParams["groupId"] != "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=" || lastParams["recipient"] != nil {
		t.Errorf("Expected /v2/send with group ID to set groupId and omit recipient, got method=%s params=%+v", lastMethod, lastParams)
	}
	rpcMu.Unlock()

	// 2. /v1/reactions/{account} with Signal username ("alice.01") passes params["recipient"] = ["alice.01"] and NOT params["groupId"]
	reactUserReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v1/reactions/+15551234567",
		strings.NewReader(`{"recipient":"alice.01","reaction":"👍","target_author":"+15559998888","timestamp":1731430000000}`))
	reactUserReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	reactUserReq.Header.Set("Content-Type", "application/json")
	reactUserRec := httptest.NewRecorder()
	handler.ServeHTTP(reactUserRec, reactUserReq)
	if reactUserRec.Code != http.StatusNoContent {
		t.Fatalf("Expected 204 No Content for username reaction, got %d (%s)", reactUserRec.Code, reactUserRec.Body.String())
	}
	rpcMu.Lock()
	rcpts, _ := lastParams["recipient"].([]interface{})
	if lastMethod != "sendReaction" || lastParams["groupId"] != nil || len(rcpts) != 1 || rcpts[0] != "alice.01" {
		t.Errorf("Expected /v1/reactions with username 'alice.01' to set recipient=['alice.01'] and omit groupId, got method=%s params=%+v", lastMethod, lastParams)
	}
	rpcMu.Unlock()

	// 3. /v1/reactions/{account} with group ID passes params["groupId"] and omits params["recipient"]
	reactGroupReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v1/reactions/+15551234567",
		strings.NewReader(`{"recipient":"group.YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=","reaction":"👍","target_author":"+15559998888","timestamp":1731430000000}`))
	reactGroupReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	reactGroupReq.Header.Set("Content-Type", "application/json")
	reactGroupRec := httptest.NewRecorder()
	handler.ServeHTTP(reactGroupRec, reactGroupReq)
	if reactGroupRec.Code != http.StatusNoContent {
		t.Fatalf("Expected 204 No Content for group reaction, got %d (%s)", reactGroupRec.Code, reactGroupRec.Body.String())
	}
	rpcMu.Lock()
	if lastMethod != "sendReaction" || lastParams["groupId"] != "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=" || lastParams["recipient"] != nil {
		t.Errorf("Expected /v1/reactions with group ID to set groupId and omit recipient, got method=%s params=%+v", lastMethod, lastParams)
	}
	rpcMu.Unlock()

	// 4. Omitting account ID on /v2/send, /v1/reactions, and /v1/receive auto-resolves the single account
	sendDefaultAcctReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send",
		strings.NewReader(`{"recipients":["+15559998888"],"message":"auto-resolved sender"}`))
	sendDefaultAcctReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	sendDefaultAcctReq.Header.Set("Content-Type", "application/json")
	sendDefaultAcctRec := httptest.NewRecorder()
	handler.ServeHTTP(sendDefaultAcctRec, sendDefaultAcctReq)
	if sendDefaultAcctRec.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created for /v2/send without number field, got %d (%s)", sendDefaultAcctRec.Code, sendDefaultAcctRec.Body.String())
	}
	rpcMu.Lock()
	if lastMethod != "send" || lastParams["account"] != "+15551234567" {
		t.Errorf("Expected /v2/send without number to auto-resolve account='+15551234567', got %+v", lastParams)
	}
	rpcMu.Unlock()

	recvDefaultAcctReq := httptest.NewRequest(http.MethodGet, "http://localhost:8080/v1/receive", nil)
	recvDefaultAcctReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	recvDefaultAcctRec := httptest.NewRecorder()
	handler.ServeHTTP(recvDefaultAcctRec, recvDefaultAcctReq)
	if recvDefaultAcctRec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for GET /v1/receive without path account, got %d (%s)", recvDefaultAcctRec.Code, recvDefaultAcctRec.Body.String())
	}

	// 5. Verify native CLI healthcheck subcommand helper
	memClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)
			return rec.Result(), nil
		}),
	}
	if err := runHealthcheckWithClient("", memClient); err != nil {
		t.Errorf("Expected runHealthcheckWithClient to succeed against /v1/health, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func strconvFormatInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestRateLimitErrorSurfacingAndChallengeSubmission(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	const acctUUID = "11111111-2222-3333-4444-555555555555"
	sendKey, err := ks.CreateKey("Sender", []string{acctUUID}, []string{"send"})
	if err != nil {
		t.Fatal(err)
	}
	adminKey, err := ks.CreateKey("Admin", []string{acctUUID}, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}

	hub := newWSHub()
	go hub.run()
	daemon := newSignalDaemon(hub)
	clientConn, daemonConn := net.Pipe()
	defer clientConn.Close()
	defer daemonConn.Close()

	daemon.mu.Lock()
	daemon.conn = clientConn
	daemon.mu.Unlock()
	go daemon.readLoop(clientConn)

	var mu sync.Mutex
	var nextSendError string
	var capturedMethod, capturedAccount, capturedChallenge, capturedCaptcha string

	go func() {
		scanner := bufio.NewScanner(daemonConn)
		for scanner.Scan() {
			var req struct {
				Method string                 `json:"method"`
				Params map[string]interface{} `json:"params"`
				ID     int64                  `json:"id"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
				continue
			}

			mu.Lock()
			sendErr := nextSendError
			if req.Method == "submitRateLimitChallenge" {
				capturedMethod = req.Method
				capturedAccount, _ = req.Params["account"].(string)
				capturedChallenge, _ = req.Params["challenge"].(string)
				capturedCaptcha, _ = req.Params["captcha"].(string)
			}
			mu.Unlock()

			var resp string
			switch {
			case req.Method == "send" && sendErr != "":
				resp = `{"jsonrpc":"2.0","error":` + sendErr + `,"id":` + strconvFormatInt(req.ID) + `}` + "\n"
			default:
				resp = `{"jsonrpc":"2.0","result":{},"id":` + strconvFormatInt(req.ID) + `}` + "\n"
			}
			_, _ = daemonConn.Write([]byte(resp))
		}
	}()

	srv := &Server{
		daemon:       daemon,
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	// 1. Upstream Signal RATE_LIMIT_FAILURE maps to 429 with Retry-After, challenge_token, and details
	mu.Lock()
	nextSendError = `{"code":-5,"message":"Failed to send message due to rate limiting","data":{"response":{"results":[{"recipientAddress":{"uuid":null,"number":"+16179496228","username":null},"type":"RATE_LIMIT_FAILURE","token":"d887e9b0-8415-471a-a0f4-ab6a7c4a2e1d","retryAfterSeconds":86400}],"timestamp":1794584710283}}}`
	mu.Unlock()

	sendReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send",
		strings.NewReader(`{"account":"`+acctUUID+`","recipients":["+16179496228"],"message":"hello"}`))
	sendReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	sendReq.Header.Set("Content-Type", "application/json")
	sendRec := httptest.NewRecorder()
	handler.ServeHTTP(sendRec, sendReq)

	if sendRec.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429 for upstream rate limit, got %d (%s)", sendRec.Code, sendRec.Body.String())
	}
	if got := sendRec.Header().Get("Retry-After"); got != "86400" {
		t.Errorf("Expected Retry-After: 86400, got %q", got)
	}
	var rlBody map[string]interface{}
	if err := json.Unmarshal(sendRec.Body.Bytes(), &rlBody); err != nil {
		t.Fatalf("Invalid JSON in 429 body: %v", err)
	}
	if rlBody["challenge_token"] != "d887e9b0-8415-471a-a0f4-ab6a7c4a2e1d" {
		t.Errorf("Expected challenge_token in 429 body, got %v", rlBody["challenge_token"])
	}
	if rlBody["retry_after_seconds"] != float64(86400) {
		t.Errorf("Expected retry_after_seconds=86400, got %v", rlBody["retry_after_seconds"])
	}
	if errStr, _ := rlBody["error"].(string); !strings.Contains(errStr, "rate limiting") {
		t.Errorf("Expected rate limiting message in error field, got %q", errStr)
	}

	// 2. Non-rate-limit JSON-RPC error surfaces upstream message on 502
	mu.Lock()
	nextSendError = `{"code":-1,"message":"Unregistered user"}`
	mu.Unlock()

	errReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v2/send",
		strings.NewReader(`{"account":"`+acctUUID+`","recipients":["+16179496228"],"message":"hello"}`))
	errReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	errReq.Header.Set("Content-Type", "application/json")
	errRec := httptest.NewRecorder()
	handler.ServeHTTP(errRec, errReq)

	if errRec.Code != http.StatusBadGateway {
		t.Fatalf("Expected 502 for non-rate-limit RPC error, got %d (%s)", errRec.Code, errRec.Body.String())
	}
	if !strings.Contains(errRec.Body.String(), "Unregistered user") {
		t.Errorf("Expected upstream RPC error message in 502 body, got %s", errRec.Body.String())
	}

	// 3. Non-admin key cannot submit rate-limit challenge
	nonAdminChallengeReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v1/accounts/rate-limit-challenge",
		strings.NewReader(`{"account":"`+acctUUID+`","challenge":"d887e9b0-8415-471a-a0f4-ab6a7c4a2e1d","captcha":"signalcaptcha://tok"}`))
	nonAdminChallengeReq.Header.Set("Authorization", "Bearer "+sendKey.Key)
	nonAdminChallengeReq.Header.Set("Content-Type", "application/json")
	nonAdminChallengeRec := httptest.NewRecorder()
	handler.ServeHTTP(nonAdminChallengeRec, nonAdminChallengeReq)
	if nonAdminChallengeRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for non-admin key on /v1/accounts/rate-limit-challenge, got %d", nonAdminChallengeRec.Code)
	}

	// 4. Missing challenge/captcha returns 400
	badChallengeReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v1/accounts/rate-limit-challenge",
		strings.NewReader(`{"account":"`+acctUUID+`","challenge":"","captcha":"signalcaptcha://tok"}`))
	badChallengeReq.Header.Set("Authorization", "Bearer "+adminKey.Key)
	badChallengeReq.Header.Set("Content-Type", "application/json")
	badChallengeRec := httptest.NewRecorder()
	handler.ServeHTTP(badChallengeRec, badChallengeReq)
	if badChallengeRec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for empty challenge, got %d", badChallengeRec.Code)
	}

	// 5. Valid admin key submits submitRateLimitChallenge with auto-resolved single-account UUID
	okChallengeReq := httptest.NewRequest(http.MethodPost, "http://localhost:8080/v1/accounts/rate-limit-challenge",
		strings.NewReader(`{"challenge":"d887e9b0-8415-471a-a0f4-ab6a7c4a2e1d","captcha":"signalcaptcha://solved-token"}`))
	okChallengeReq.Header.Set("Authorization", "Bearer "+adminKey.Key)
	okChallengeReq.Header.Set("Content-Type", "application/json")
	okChallengeRec := httptest.NewRecorder()
	handler.ServeHTTP(okChallengeRec, okChallengeReq)
	if okChallengeRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 from /v1/accounts/rate-limit-challenge, got %d (%s)", okChallengeRec.Code, okChallengeRec.Body.String())
	}

	mu.Lock()
	if capturedMethod != "submitRateLimitChallenge" || capturedAccount != acctUUID ||
		capturedChallenge != "d887e9b0-8415-471a-a0f4-ab6a7c4a2e1d" || capturedCaptcha != "signalcaptcha://solved-token" {
		t.Errorf("Unexpected RPC params: method=%q account=%q challenge=%q captcha=%q",
			capturedMethod, capturedAccount, capturedChallenge, capturedCaptcha)
	}
	mu.Unlock()
}






