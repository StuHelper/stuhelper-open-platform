package openplatform_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/auditquery"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMalformedUTF8NullBytesSingleLineFieldsClosureKeyAndAuditSnapshotValidation(t *testing.T) {
	x := setup(t)
	s := x.s
	h := httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (op.Principal, error) {
			if r.Header.Get("Authorization") == "Bearer session-alice" {
				return alice, nil
			}
			return op.Principal{}, op.ErrUnauthenticated
		},
	}

	// 1. A-05: Invalid UTF-8 (%FF) and null bytes (%00 / \u0000) in path IDs, cursors, Idempotency-Key,
	// ClientID, RedirectURI, and Query.After must return 400 invalid_input instead of PostgreSQL 22021 -> 503.
	for _, badPath := range []string{
		"/api/v1/open-platform/apps/%FF",
		"/api/v1/open-platform/apps/a%00b",
		"/api/v1/open-platform/apps?after=%FF",
		"/api/v1/open-platform/consents/%FF",
		"/api/v1/open-platform/grants?after=%FF",
	} {
		req := httptest.NewRequest("GET", badPath, nil)
		req.Header.Set("Authorization", "Bearer session-alice")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("GET %s expected 400 invalid_input, got %d %s", badPath, w.Code, w.Body.String())
		}
	}

	// Invalid UTF-8 in Idempotency-Key header.
	reqBadKey := httptest.NewRequest("POST", "/api/v1/open-platform/apps", strings.NewReader(`{"name":"Valid","purpose":"test","redirect_uris":["https://x.example/cb"],"requested_scopes":["profile"],"client_type":"public"}`))
	reqBadKey.Header.Set("Authorization", "Bearer session-alice")
	reqBadKey.Header.Set("Content-Type", "application/json")
	reqBadKey.Header.Set("Idempotency-Key", "bad-\xff-key")
	wBadKey := httptest.NewRecorder()
	h.ServeHTTP(wBadKey, reqBadKey)
	if wBadKey.Code != 400 {
		t.Fatalf("expected 400 for invalid UTF-8 Idempotency-Key, got %d %s", wBadKey.Code, wBadKey.Body.String())
	}

	// Null byte in ConsentInput.client_id must return ErrInput (400), never 503 ErrUnavailable.
	sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if _, err := s.PrepareConsent(ctx, alice, "null-client", op.ConsentInput{
		ClientID:    "app\x00id",
		RedirectURI: "https://x.example/cb",
		State:       strings.Repeat("s", 16),
		Scopes:      []string{"profile"},
		Challenge:   challenge,
		Method:      "S256",
	}); !errors.Is(err, op.ErrInput) {
		t.Fatalf("expected ErrInput for null byte in ClientID, got %v", err)
	}

	// Invalid UTF-8 or control char in Read Query.After must return ErrInput (400).
	app := approve(t, s, apply(t, s, dev, "utf8-app", []string{"catalog"}, "public"), []string{"catalog"}, 100)
	tok := tokenFor(t, s, alice, app, "utf8-tok", []string{"catalog"})
	for _, badAfter := range []string{"\xff", "cursor\x00tail", "cursor\nline"} {
		if _, err := s.Read(ctx, tok.AccessToken, "catalog", op.Query{After: badAfter}); !errors.Is(err, op.ErrInput) {
			t.Fatalf("expected ErrInput for bad Query.After %q, got %v", badAfter, err)
		}
	}

	// 2. A-05(2): ReadAudit must reject invalid UTF-8 in filters and syntactically invalid Snapshot with auditquery.ErrInvalid,
	// while a syntactically valid Snapshot with a mismatched epoch returns auditquery.ErrUnavailable.
	scopes := []auditquery.Scope{{School: "*", Group: "*", Module: "open-platform"}}
	until := s.Now().Add(time.Minute)
	if _, err := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Actor: "bad\xffactor", Until: until, Limit: 10}); !errors.Is(err, auditquery.ErrInvalid) {
		t.Fatalf("expected auditquery.ErrInvalid for non-UTF8 Actor, got %v", err)
	}
	for _, badSnap := range []string{"malformed", "0|invalid", "-1|10:20:", "0|20:10:", "0|10:20:abc", "0|10:20:25", "0|10:20:15,12"} {
		if _, err := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Snapshot: badSnap, Until: until, Limit: 10}); !errors.Is(err, auditquery.ErrInvalid) {
			t.Fatalf("Snapshot %q expected auditquery.ErrInvalid, got %v", badSnap, err)
		}
	}
	if _, err := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Snapshot: "999|10:20:", Until: until, Limit: 10}); !errors.Is(err, auditquery.ErrUnavailable) {
		t.Fatalf("stale epoch Snapshot expected auditquery.ErrUnavailable, got %v", err)
	}

	// 3. A-11(1): Single-line fields (Application.Name, ConsentInput.State, Query filters, closureID) must reject \n and \t,
	// whereas multi-line Purpose continues to allow \n.
	if _, err := s.Apply(ctx, dev, "", "multiline-name", op.ApplicationInput{
		Name:            "课表查询\n[官方认证]",
		Purpose:         "Multi-line\npurpose is valid",
		RedirectURIs:    []string{"https://client.example/cb"},
		RequestedScopes: []string{"profile"},
		ClientType:      "public",
	}); !errors.Is(err, op.ErrInput) {
		t.Fatalf("expected ErrInput for multiline Application.Name, got %v", err)
	}
	if _, err := s.PrepareConsent(ctx, alice, "multiline-state", op.ConsentInput{
		ClientID:    app.ID,
		RedirectURI: app.RedirectURIs[0],
		State:       "state-with-newline\ninjected",
		Scopes:      []string{"catalog"},
		Challenge:   challenge,
		Method:      "S256",
	}); !errors.Is(err, op.ErrInput) {
		t.Fatalf("expected ErrInput for newline in ConsentInput.State, got %v", err)
	}
	if _, err := s.Read(ctx, tok.AccessToken, "catalog", op.Query{TermID: "2026\tfall"}); !errors.Is(err, op.ErrInput) {
		t.Fatalf("expected ErrInput for tab in Query.TermID, got %v", err)
	}
	if err := s.CloseAccount(ctx, bob.Owner, "closure\tid"); !errors.Is(err, op.ErrInput) {
		t.Fatalf("expected ErrInput for tab in closureID, got %v", err)
	}

	// 4. A-11(2): CloseAccount with a valid 128-character ASCII or multi-byte UTF-8 closureID must succeed idempotently
	// without colliding with replay's 128-byte key ceiling, and reject a different closureID with ErrConflict.
	longClosureID := strings.Repeat("闭", 128) // 128 runes = 384 UTF-8 bytes
	for range 2 {
		if err := s.CloseAccount(ctx, bob.Owner, longClosureID); err != nil {
			t.Fatalf("128-rune closureID failed: %v", err)
		}
	}
	var storedClosure string
	if err := x.db.QueryRow(`SELECT closure_id FROM open_platform.owners WHERE owner_key=$1`, bob.Owner).Scan(&storedClosure); err != nil || storedClosure != longClosureID {
		t.Fatalf("unexpected stored closure_id: err=%v len=%d", err, len(storedClosure))
	}
	if err := s.CloseAccount(ctx, bob.Owner, strings.Repeat("c", 125)); !errors.Is(err, op.ErrConflict) {
		t.Fatalf("expected ErrConflict for mismatched second closureID, got %v", err)
	}
}
