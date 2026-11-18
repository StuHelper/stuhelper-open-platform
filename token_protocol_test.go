package openplatform_test

import (
	"context"
	"encoding/json"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTokenEndpointAcceptsBrowserFormMediaTypeAndMapsTransientErrorsTo503(t *testing.T) {
	x := setup(t)
	s := x.s
	h := httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (op.Principal, error) {
			if r.Header.Get("Authorization") == "Bearer session-dev" {
				return dev, nil
			}
			return op.Principal{}, op.ErrUnauthenticated
		},
	}

	// JSON media type with uppercase type and charset=utf-8 must succeed; application/jsonl must be rejected.
	badJSON := httptest.NewRequest("POST", "/api/v1/open-platform/apps", strings.NewReader(`{"name":"Bad","purpose":"test","redirect_uris":["https://x.example/cb"],"requested_scopes":["profile"],"client_type":"public"}`))
	badJSON.Header.Set("Authorization", "Bearer session-dev")
	badJSON.Header.Set("Content-Type", "application/jsonl")
	badJSON.Header.Set("Idempotency-Key", "jsonl-reject")
	wBad := httptest.NewRecorder()
	h.ServeHTTP(wBad, badJSON)
	if wBad.Code != 400 || count(t, x.db, `SELECT count(*) FROM open_platform.apps`) != 0 {
		t.Fatalf("expected 400 for application/jsonl without DB write, got %d %s", wBad.Code, wBad.Body.String())
	}

	goodJSON := httptest.NewRequest("POST", "/api/v1/open-platform/apps", strings.NewReader(`{"name":"Browser SPA","purpose":"test","redirect_uris":["https://spa.example/cb"],"requested_scopes":["profile"],"client_type":"public"}`))
	goodJSON.Header.Set("Authorization", "Bearer session-dev")
	goodJSON.Header.Set("Content-Type", "Application/JSON; charset=UTF-8")
	goodJSON.Header.Set("Idempotency-Key", "json-charset-ok")
	wGood := httptest.NewRecorder()
	h.ServeHTTP(wGood, goodJSON)
	if wGood.Code != 200 {
		t.Fatalf("expected 200 for Application/JSON; charset=UTF-8, got %d %s", wGood.Code, wGood.Body.String())
	}
	var created op.Application
	if err := json.Unmarshal(wGood.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	app := approve(t, s, created, []string{"profile"}, 100)

	// 1. Browser URLSearchParams Content-Type: application/x-www-form-urlencoded;charset=UTF-8
	_, code1, verifier1 := consent(t, s, alice, app, "browser-fetch", []string{"profile"})
	form1 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {app.ID},
		"redirect_uri":  {app.RedirectURIs[0]},
		"code":          {code1},
		"code_verifier": {verifier1},
	}.Encode()
	req1 := httptest.NewRequest("POST", "/api/v1/open-platform/token", strings.NewReader(form1))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("browser URLSearchParams Content-Type rejected: %d %s", w1.Code, w1.Body.String())
	}
	var tok1 op.Token
	if err := json.Unmarshal(w1.Body.Bytes(), &tok1); err != nil || tok1.AccessToken == "" {
		t.Fatalf("invalid token response: %v %s", err, w1.Body.String())
	}
	if _, err := s.Read(ctx, tok1.AccessToken, "profile", op.Query{}); err != nil {
		t.Fatalf("issued token unusable: %v", err)
	}

	// Non-UTF-8 charset on /token must still be rejected with 400 invalid_request.
	reqBadCharset := httptest.NewRequest("POST", "/api/v1/open-platform/token", strings.NewReader(form1))
	reqBadCharset.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=iso-8859-1")
	wBadCharset := httptest.NewRecorder()
	h.ServeHTTP(wBadCharset, reqBadCharset)
	if wBadCharset.Code != 400 || !strings.Contains(wBadCharset.Body.String(), `"invalid_request"`) {
		t.Fatalf("expected 400 invalid_request for non-utf8 charset, got %d %s", wBadCharset.Code, wBadCharset.Body.String())
	}

	// 2. Database lock timeout (context.DeadlineExceeded) and serialization conflict (40001 -> ErrConflict)
	// must map to 503 temporarily_unavailable without consuming the authorization code.
	_, code2, verifier2 := consent(t, s, bob, app, "transient-lock", []string{"profile"})
	form2 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {app.ID},
		"redirect_uri":  {app.RedirectURIs[0]},
		"code":          {code2},
		"code_verifier": {verifier2},
	}.Encode()

	tx, err := x.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "open-platform-owner:"+bob.Owner); err != nil {
		t.Fatal(err)
	}
	shortCtx, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	reqTimeout := httptest.NewRequest("POST", "/api/v1/open-platform/token", strings.NewReader(form2)).WithContext(shortCtx)
	reqTimeout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wTimeout := httptest.NewRecorder()
	h.ServeHTTP(wTimeout, reqTimeout)
	if wTimeout.Code != 503 || !strings.Contains(wTimeout.Body.String(), `"temporarily_unavailable"`) {
		t.Fatalf("expected 503 temporarily_unavailable on DB lock timeout, got %d %s", wTimeout.Code, wTimeout.Body.String())
	}
	_ = tx.Rollback()

	if _, err := x.db.Exec(`CREATE FUNCTION open_platform.raise_serialization() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'serialization_failure' USING ERRCODE = '40001'; END $$; CREATE TRIGGER transient_conflict BEFORE INSERT ON open_platform.tokens FOR EACH ROW EXECUTE FUNCTION open_platform.raise_serialization()`); err != nil {
		t.Fatal(err)
	}
	reqConflict := httptest.NewRequest("POST", "/api/v1/open-platform/token", strings.NewReader(form2))
	reqConflict.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wConflict := httptest.NewRecorder()
	h.ServeHTTP(wConflict, reqConflict)
	if _, err := x.db.Exec(`DROP TRIGGER transient_conflict ON open_platform.tokens; DROP FUNCTION open_platform.raise_serialization()`); err != nil {
		t.Fatal(err)
	}
	if wConflict.Code != 503 || !strings.Contains(wConflict.Body.String(), `"temporarily_unavailable"`) {
		t.Fatalf("expected 503 temporarily_unavailable on SQLSTATE 40001, got %d %s", wConflict.Code, wConflict.Body.String())
	}

	// Because both transient errors rolled back, retrying with the same code must succeed!
	reqRetry := httptest.NewRequest("POST", "/api/v1/open-platform/token", strings.NewReader(form2))
	reqRetry.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	wRetry := httptest.NewRecorder()
	h.ServeHTTP(wRetry, reqRetry)
	if wRetry.Code != 200 {
		t.Fatalf("expected code to remain unconsumed after transient 503s, got %d %s", wRetry.Code, wRetry.Body.String())
	}
}
