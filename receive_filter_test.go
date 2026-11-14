package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestReceiveFilteringAndLimit(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := newKeyStore(filepath.Join(tmpDir, "api_keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	hub := newWSHub()
	go hub.run()

	acct := "+15550001111"
	key, err := ks.CreateKey("Receive Filter Key", []string{acct}, []string{"receive"})
	if err != nil {
		t.Fatal(err)
	}

	// Ensure Published messages are strictly after key.CreatedAt
	time.Sleep(10 * time.Millisecond)

	messages := []string{
		// 0: Alice dataMessage (text)
		`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"source":"+15551110001","sourceNumber":"+15551110001","sourceUuid":"aaaaaaaa-1111-2222-3333-444444444441","sourceName":"Alice","timestamp":1001,"dataMessage":{"timestamp":1001,"message":"msg-1"}}}}`,
		// 1: Alice reaction (inside dataMessage)
		`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"source":"+15551110001","sourceNumber":"+15551110001","sourceUuid":"aaaaaaaa-1111-2222-3333-444444444441","sourceName":"Alice","timestamp":1002,"dataMessage":{"timestamp":1002,"reaction":{"emoji":"👍","targetAuthor":"+15550001111","targetSentTimestamp":1000,"isRemove":false}}}}}`,
		// 2: Bob typingMessage (no dataMessage, no reaction)
		`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"source":"+15551110002","sourceNumber":"+15551110002","sourceUuid":"bbbbbbbb-1111-2222-3333-444444444442","sourceName":"Bob","timestamp":1003,"typingMessage":{"action":"STARTED","timestamp":1003}}}}`,
		// 3: Bob dataMessage (text)
		`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"source":"+15551110002","sourceNumber":"+15551110002","sourceUuid":"bbbbbbbb-1111-2222-3333-444444444442","sourceName":"Bob","timestamp":1004,"dataMessage":{"timestamp":1004,"message":"msg-2"}}}}`,
		// 4: Alice dataMessage (text, newer)
		`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"source":"+15551110001","sourceNumber":"+15551110001","sourceUuid":"aaaaaaaa-1111-2222-3333-444444444441","sourceName":"Alice","timestamp":1005,"dataMessage":{"timestamp":1005,"message":"msg-3"}}}}`,
		// 5: Bob reaction
		`{"jsonrpc":"2.0","method":"receive","params":{"account":"+15550001111","envelope":{"source":"+15551110002","sourceNumber":"+15551110002","sourceUuid":"bbbbbbbb-1111-2222-3333-444444444442","sourceName":"Bob","timestamp":1006,"dataMessage":{"timestamp":1006,"reaction":{"emoji":"🎉","targetAuthor":"+15550001111","targetSentTimestamp":1005,"isRemove":false}}}}}`,
	}

	for _, m := range messages {
		hub.Publish("", []byte(m))
	}

	srv := &Server{
		daemon:       newSignalDaemon(hub),
		hub:          hub,
		keyStore:     ks,
		sessionStore: newSessionStore(time.Minute),
		apiKeyMgmt:   testRootKey,
	}
	handler := srv.Handler()

	doReceive := func(pathAndQuery string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080"+pathAndQuery, nil)
		req.Header.Set("Authorization", "Bearer "+key.Key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	extractTimestamps := func(t *testing.T, body []byte) []int64 {
		t.Helper()
		var items []struct {
			Params struct {
				Envelope struct {
					Timestamp int64 `json:"timestamp"`
				} `json:"envelope"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &items); err != nil {
			t.Fatalf("failed to decode JSON array: %v (body=%s)", err, string(body))
		}
		out := make([]int64, len(items))
		for i, it := range items {
			out[i] = it.Params.Envelope.Timestamp
		}
		return out
	}

	assertTimestamps := func(t *testing.T, query string, want []int64) {
		t.Helper()
		rec := doReceive(query)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: expected 200, got %d (%s)", query, rec.Code, rec.Body.String())
		}
		got := extractTimestamps(t, rec.Body.Bytes())
		if len(got) != len(want) {
			t.Fatalf("GET %s: expected timestamps %v, got %v", query, want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("GET %s: expected timestamps %v, got %v", query, want, got)
			}
		}
	}

	// 1. No filters returns all 6 in chronological order
	assertTimestamps(t, "/v1/receive/"+acct, []int64{1001, 1002, 1003, 1004, 1005, 1006})

	// 2. Limit to X most recent items (both /v1/receive/{number} and /v1/receive)
	assertTimestamps(t, "/v1/receive/"+acct+"?limit=2", []int64{1005, 1006})
	assertTimestamps(t, "/v1/receive?limit=3", []int64{1004, 1005, 1006})
	assertTimestamps(t, "/v1/receive/"+acct+"?limit=100", []int64{1001, 1002, 1003, 1004, 1005, 1006})

	// 3. Single field filters
	assertTimestamps(t, "/v1/receive/"+acct+"?source=%2B15551110001", []int64{1001, 1002, 1005})
	assertTimestamps(t, "/v1/receive/"+acct+"?sourceNumber=%2B15551110002", []int64{1003, 1004, 1006})
	assertTimestamps(t, "/v1/receive/"+acct+"?sourceUuid=AAAAAAAA-1111-2222-3333-444444444441", []int64{1001, 1002, 1005})
	assertTimestamps(t, "/v1/receive/"+acct+"?sourceName=Bob", []int64{1003, 1004, 1006})
	assertTimestamps(t, "/v1/receive/"+acct+"?dataMessage=true", []int64{1001, 1002, 1004, 1005, 1006})
	assertTimestamps(t, "/v1/receive/"+acct+"?dataMessage=false", []int64{1003})
	assertTimestamps(t, "/v1/receive/"+acct+"?reaction=true", []int64{1002, 1006})
	assertTimestamps(t, "/v1/receive/"+acct+"?reaction=false", []int64{1001, 1003, 1004, 1005})

	// 4. Combined AND filters + limit
	assertTimestamps(t, "/v1/receive/"+acct+"?sourceName=Alice&dataMessage=true&reaction=false", []int64{1001, 1005})
	assertTimestamps(t, "/v1/receive/"+acct+"?sourceName=Alice&dataMessage=true&reaction=false&limit=1", []int64{1005})
	assertTimestamps(t, "/v1/receive/"+acct+"?source=%2B15551110002&sourceNumber=%2B15551110002&sourceUuid=bbbbbbbb-1111-2222-3333-444444444442&sourceName=Bob&reaction=true", []int64{1006})

	// 5. Empty match returns [] (not null)
	rec := doReceive("/v1/receive/" + acct + "?sourceName=Charlie")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty match, got %d", rec.Code)
	}
	if stringsTrimSpace := rec.Body.String(); stringsTrimSpace != "[]\n" {
		t.Errorf("expected empty JSON array [], got %q", stringsTrimSpace)
	}

	// 6. Invalid query parameters return 400 Bad Request
	invalidQueries := []string{
		"/v1/receive/" + acct + "?limit=0",
		"/v1/receive/" + acct + "?limit=-3",
		"/v1/receive/" + acct + "?limit=abc",
		"/v1/receive/" + acct + "?source=",
		"/v1/receive/" + acct + "?sourceNumber=",
		"/v1/receive/" + acct + "?sourceUuid=",
		"/v1/receive/" + acct + "?sourceName=",
		"/v1/receive/" + acct + "?dataMessage=yes",
		"/v1/receive/" + acct + "?reaction=1",
	}
	for _, q := range invalidQueries {
		badRec := doReceive(q)
		if badRec.Code != http.StatusBadRequest {
			t.Errorf("GET %s: expected 400 Bad Request, got %d (%s)", q, badRec.Code, badRec.Body.String())
		}
	}
}
