package openplatform_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProblemReasonSubcodesAndQuotaRetryAfterHeader(t *testing.T) {
	x := setup(t)
	s := x.s
	currentUser := dev
	h := httpapi.Handler{Service: s, Authenticate: func(r *http.Request) (op.Principal, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer admin":
			return admin, nil
		case "Bearer dev":
			return dev, nil
		case "Bearer alice":
			return alice, nil
		case "Bearer bob":
			return bob, nil
		case "Bearer dynamic":
			return currentUser, nil
		default:
			return op.Principal{}, op.ErrUnauthenticated
		}
	}}
	expectProblem := func(method, path, auth, key, body string, wantStatus int, wantCode, wantReason string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1/open-platform"+path, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != wantStatus {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, w.Code, wantStatus, w.Body.String())
		}
		var prob op.Problem
		if err := json.Unmarshal(w.Body.Bytes(), &prob); err != nil {
			t.Fatalf("%s %s: invalid problem JSON: %v (%s)", method, path, err, w.Body.String())
		}
		if prob.Code != wantCode || prob.Reason != wantReason {
			t.Fatalf("%s %s: got problem=%+v want code=%q reason=%q", method, path, prob, wantCode, wantReason)
		}
		return w
	}

	verifier := strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// 1. admin_required & application_inactive
	expectProblem(http.MethodGet, "/admin/apps", "Bearer dev", "", "", http.StatusForbidden, "forbidden", "admin_required")
	app := apply(t, s, dev, "app-reasons", []string{"profile", "catalog", "student_status"}, "public")
	consentPayload := func(uri string, sc string) string {
		return fmt.Sprintf(`{"client_id":%q,"redirect_uri":%q,"state":%q,"scope":[%q],"code_challenge":%q,"code_challenge_method":"S256"}`, app.ID, uri, strings.Repeat("s", 16), sc, challenge)
	}
	expectProblem(http.MethodPost, "/consents", "Bearer alice", "inactive-app", consentPayload(app.RedirectURIs[0], "profile"), http.StatusForbidden, "forbidden", "application_inactive")

	// 2. idempotency_conflict & revision_mismatch & state_conflict on app/credential/review
	expectProblem(http.MethodPost, "/apps", "Bearer dev", "app-reasons", `{"name":"Different","purpose":"different","redirect_uris":["https://client.example/callback"],"requested_scopes":["profile"],"client_type":"public"}`, http.StatusConflict, "conflict", "idempotency_conflict")
	expectProblem(http.MethodPost, "/apps/"+app.ID+"/submit", "Bearer dev", "bad-sub-rev", `{"name":"X","purpose":"p","redirect_uris":["https://client.example/callback"],"requested_scopes":["profile"],"client_type":"public","revision":99}`, http.StatusConflict, "conflict", "revision_mismatch")
	expectProblem(http.MethodPost, "/admin/apps/"+app.ID+"/review", "Bearer admin", "bad-rev", `{"revision":99,"decision":"suspend","approved_scopes":[],"policy":{"grant_seconds":0,"token_seconds":0,"daily_quota":0},"note":"n"}`, http.StatusConflict, "conflict", "revision_mismatch")
	expectProblem(http.MethodPost, "/apps/"+app.ID+"/credential", "Bearer dev", "bad-cred-rev", `{"revision":5}`, http.StatusConflict, "conflict", "revision_mismatch")

	app = approve(t, s, app, []string{"profile", "catalog"}, 1)
	expectProblem(http.MethodPost, "/apps/"+app.ID+"/submit", "Bearer dev", "active-submit", fmt.Sprintf(`{"name":"X","purpose":"p","redirect_uris":["https://client.example/callback"],"requested_scopes":["profile"],"client_type":"public","revision":%d}`, app.Revision), http.StatusConflict, "conflict", "state_conflict")

	// 3. redirect_uri_mismatch & scope_not_authorized on consent preparation/decision
	expectProblem(http.MethodPost, "/consents", "Bearer alice", "bad-uri", consentPayload("https://evil.example/cb", "profile"), http.StatusForbidden, "forbidden", "redirect_uri_mismatch")
	expectProblem(http.MethodPost, "/consents", "Bearer alice", "bad-scope", consentPayload(app.RedirectURIs[0], "student_status"), http.StatusForbidden, "forbidden", "scope_not_authorized")

	c1, e := s.PrepareConsent(ctx, alice, "c-widen", op.ConsentInput{ClientID: app.ID, RedirectURI: app.RedirectURIs[0], State: strings.Repeat("s", 16), Scopes: []string{"profile"}, Challenge: challenge, Method: "S256"})
	if e != nil {
		t.Fatal(e)
	}
	expectProblem(http.MethodPost, "/consents/"+c1.ID+"/decision", "Bearer alice", "dec-widen", `{"decision":"approve","scopes":["catalog"]}`, http.StatusForbidden, "forbidden", "scope_not_authorized")
	if _, e = s.Decide(ctx, alice, c1.ID, "dec-ok", op.ConsentDecision{Decision: "deny", Scopes: []string{}}); e != nil {
		t.Fatal(e)
	}
	expectProblem(http.MethodPost, "/consents/"+c1.ID+"/decision", "Bearer alice", "dec-twice", `{"decision":"deny","scopes":[]}`, http.StatusConflict, "conflict", "consent_already_decided")

	// 4. consent_expired & application_revision_changed
	cExp, e := s.PrepareConsent(ctx, alice, "c-exp", op.ConsentInput{ClientID: app.ID, RedirectURI: app.RedirectURIs[0], State: strings.Repeat("s", 16), Scopes: []string{"profile"}, Challenge: challenge, Method: "S256"})
	if e != nil {
		t.Fatal(e)
	}
	x.clock.Add(301)
	expectProblem(http.MethodGet, "/consents/"+cExp.ID, "Bearer alice", "", "", http.StatusConflict, "conflict", "consent_expired")
	expectProblem(http.MethodPost, "/consents/"+cExp.ID+"/decision", "Bearer alice", "dec-exp", `{"decision":"deny","scopes":[]}`, http.StatusConflict, "conflict", "consent_expired")

	cRev, e := s.PrepareConsent(ctx, alice, "c-rev", op.ConsentInput{ClientID: app.ID, RedirectURI: app.RedirectURIs[0], State: strings.Repeat("s", 16), Scopes: []string{"profile"}, Challenge: challenge, Method: "S256"})
	if e != nil {
		t.Fatal(e)
	}
	app = approve(t, s, app, []string{"profile", "catalog"}, 2)
	expectProblem(http.MethodPost, "/consents/"+cRev.ID+"/decision", "Bearer alice", "dec-app-rev", `{"decision":"approve","scopes":["profile"]}`, http.StatusConflict, "conflict", "application_revision_changed")

	// 5. scope_not_authorized vs content_admission_denied (OP-05) & daily_quota_exceeded + Retry-After
	x.clock.Store(time.Date(2026, 11, 1, 23, 50, 0, 0, time.UTC).Unix())
	tokProfile := tokenFor(t, s, alice, app, "tok-profile", []string{"profile"})
	expectProblem(http.MethodGet, "/data/catalog", "Bearer "+tokProfile.AccessToken, "", "", http.StatusForbidden, "forbidden", "scope_not_authorized")

	tokCatalog := tokenFor(t, s, bob, app, "tok-catalog", []string{"catalog"})
	x.source.state.Store(1)
	expectProblem(http.MethodGet, "/data/catalog", "Bearer "+tokCatalog.AccessToken, "", "", http.StatusForbidden, "forbidden", "content_admission_denied")
	x.source.state.Store(0)

	// One quota unit was consumed by content_admission_denied above; consume second unit at 23:50:00 UTC, then trigger 429.
	if _, e = s.Read(ctx, tokProfile.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal(e)
	}
	w429 := expectProblem(http.MethodGet, "/data/profile", "Bearer "+tokProfile.AccessToken, "", "", http.StatusTooManyRequests, "quota_exceeded", "daily_quota_exceeded")
	if got := w429.Header().Get("Retry-After"); got != "600" {
		t.Fatalf("Retry-After = %q, want 600", got)
	}

	// 6. revoke revision_mismatch & notice state_conflict
	gs, e := s.Grants(ctx, alice, "", 10)
	if e != nil || len(gs.Items) != 1 {
		t.Fatal(gs, e)
	}
	expectProblem(http.MethodPost, "/grants/"+gs.Items[0].ID+"/revoke", "Bearer alice", "bad-grant-rev", `{"revision":999,"scopes":["profile"]}`, http.StatusConflict, "conflict", "revision_mismatch")
	if _, e = s.Revoke(ctx, alice, gs.Items[0].ID, "ok-grant-rev", op.RevokeInput{Revision: gs.Items[0].Revision, Scopes: []string{"profile"}}); e != nil {
		t.Fatal(e)
	}
	notices, e := s.Notices(ctx, dev, app.ID, "", "", 10)
	if e != nil || len(notices.Items) == 0 {
		t.Fatal(notices, e)
	}
	if _, e = s.Acknowledge(ctx, dev, app.ID, "", notices.Items[0].ID, "ack-del", op.Acknowledgement{Status: "deleted", Note: ""}); e != nil {
		t.Fatal(e)
	}
	expectProblem(http.MethodPost, "/apps/"+app.ID+"/notices/"+notices.Items[0].ID+"/ack", "Bearer dev", "ack-downgrade", `{"status":"received","note":""}`, http.StatusConflict, "conflict", "state_conflict")

	// 7. application_limit_reached, pending_consent_limit_reached, and account_closed
	capDev := op.Principal{Owner: "cap-developer"}
	currentUser = capDev
	for i := range 100 {
		if _, e = s.Apply(ctx, capDev, "", fmt.Sprintf("cap-%d", i), op.ApplicationInput{Name: "App", Purpose: "p", RedirectURIs: []string{"https://client.example/cb"}, RequestedScopes: []string{"profile"}, ClientType: "public"}); e != nil {
			t.Fatal(i, e)
		}
	}
	expectProblem(http.MethodPost, "/apps", "Bearer dynamic", "cap-101", `{"name":"App","purpose":"p","redirect_uris":["https://client.example/cb"],"requested_scopes":["profile"],"client_type":"public"}`, http.StatusConflict, "conflict", "application_limit_reached")

	capUser := op.Principal{Owner: "cap-user"}
	currentUser = capUser
	for i := range 100 {
		if _, e = s.PrepareConsent(ctx, capUser, fmt.Sprintf("pc-%d", i), op.ConsentInput{ClientID: app.ID, RedirectURI: app.RedirectURIs[0], State: strings.Repeat("s", 16), Scopes: []string{"profile"}, Challenge: challenge, Method: "S256"}); e != nil {
			t.Fatal(i, e)
		}
	}
	expectProblem(http.MethodPost, "/consents", "Bearer dynamic", "pc-101", consentPayload(app.RedirectURIs[0], "profile"), http.StatusConflict, "conflict", "pending_consent_limit_reached")

	if e = s.CloseAccount(ctx, capUser.Owner, "close-cap-user"); e != nil {
		t.Fatal(e)
	}
	if e = s.CloseAccount(ctx, capUser.Owner, "different-closure"); !errors.Is(e, op.ErrConflict) || op.ErrorReason(e) != "idempotency_conflict" {
		t.Fatalf("expected CloseAccount conflict reason idempotency_conflict, got %v (%q)", e, op.ErrorReason(e))
	}
	expectProblem(http.MethodGet, "/grants", "Bearer dynamic", "", "", http.StatusForbidden, "forbidden", "account_closed")
}
