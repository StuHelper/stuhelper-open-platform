package openplatform_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"github.com/StuHelper/stuhelper-open-platform/postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type source struct {
	state   atomic.Int32
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (s *source) Read(ctx context.Context, owner, scope string, q op.Query) (op.Data, error) {
	s.calls.Add(1)
	if _, ok := ctx.Deadline(); !ok {
		return op.Data{}, errors.New("missing deadline")
	}
	if s.state.Load() == 1 {
		return op.Data{}, op.ErrForbidden
	}
	if s.state.Load() == 2 {
		return op.Data{}, op.ErrUnavailable
	}
	if s.entered != nil {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return op.Data{}, ctx.Err()
		}
	}
	switch scope {
	case "profile":
		return op.Data{Profile: &op.Profile{ID: "public-" + owner, Nickname: owner, Bio: "Synthetic profile"}, QQBinding: &op.QQBinding{Bound: true, Number: "123456"}}, nil
	case "qq_binding":
		return op.Data{QQBinding: &op.QQBinding{Bound: true, Number: "123456"}}, nil
	default:
		return op.Data{StudentStatus: &op.StudentStatus{Verified: true, EvaluatedAt: time.Now()}}, nil
	}
}

type fixture struct {
	s      *op.Service
	source *source
	db     *sql.DB
	repo   *postgres.Repository
	clock  *atomic.Int64
}

func setup(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("STUHELPER_OPEN_PLATFORM_TEST_DSN")
	if dsn == "" {
		t.Fatal("isolated PostgreSQL required")
	}
	admin, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("openplat_%d", time.Now().UnixNano())
	if _, e = admin.Exec(`CREATE DATABASE ` + name); e != nil {
		t.Fatal(e)
	}
	owner, e := sql.Open("pgx", dsn+" dbname="+name)
	if e != nil {
		t.Fatal(e)
	}
	role := name + "_runtime"
	t.Cleanup(func() {
		owner.Close()
		admin.Exec(`DROP DATABASE ` + name + ` WITH(FORCE)`)
		admin.Exec(`DROP ROLE ` + role)
		admin.Close()
	})
	for range 2 {
		if e = postgres.Migrate(context.Background(), owner); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = owner.Exec(`CREATE ROLE ` + role + ` LOGIN;REVOKE ALL ON SCHEMA public FROM PUBLIC;GRANT USAGE ON SCHEMA open_platform TO ` + role + `;GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA open_platform TO ` + role + `;GRANT USAGE ON ALL SEQUENCES IN SCHEMA open_platform TO ` + role + `;REVOKE UPDATE ON open_platform.events,open_platform.requests,open_platform.tokens FROM ` + role + `;CREATE SCHEMA foreign_data;CREATE TABLE foreign_data.secret(value text);`); e != nil {
		t.Fatal(e)
	}
	runtime, e := sql.Open("pgx", dsn+" dbname="+name+" user="+role)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { runtime.Close() })
	repo := &postgres.Repository{DB: runtime}
	if e = repo.CheckRuntime(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = (&postgres.Repository{DB: owner}).CheckRuntime(context.Background()); e == nil {
		t.Fatal("migration identity accepted")
	}
	if _, e = runtime.Exec(`SELECT * FROM foreign_data.secret`); e == nil {
		t.Fatal("foreign schema readable")
	}
	src := &source{}
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix())
	s := &op.Service{Repo: repo, Source: src, CodeKey: []byte(strings.Repeat("k", 32)), Issuer: "https://issuer.example/open-platform", Now: func() time.Time { return time.Unix(clock.Load(), 0).UTC() }}
	return fixture{s, src, owner, repo, clock}
}

var ctx = context.Background()
var admin = op.Principal{Owner: "administrator", Admin: true}
var dev = op.Principal{Owner: "developer"}
var alice = op.Principal{Owner: "alice"}
var bob = op.Principal{Owner: "bob"}

func apply(t *testing.T, s *op.Service, owner op.Principal, key string, scopes []string, client string) op.Application {
	t.Helper()
	a, e := s.Apply(ctx, owner, "", key, op.ApplicationInput{Name: "Synthetic application", Purpose: "Read explicitly selected facts", RedirectURIs: []string{"https://client.example/callback"}, RequestedScopes: scopes, ClientType: client})
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func approve(t *testing.T, s *op.Service, a op.Application, scopes []string, quota int) op.Application {
	t.Helper()
	v, e := s.Review(ctx, admin, a.ID, "approve:"+a.ID+fmt.Sprint(a.Revision), op.ReviewInput{Revision: a.Revision, Decision: "approve", ApprovedScopes: scopes, Policy: op.Policy{GrantSeconds: 600, TokenSeconds: 600, DailyQuota: quota}, Note: "Reviewed synthetic purpose"})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func consent(t *testing.T, s *op.Service, p op.Principal, a op.Application, key string, scopes []string) (op.Consent, string, string) {
	t.Helper()
	verifier := strings.Repeat("a", 43)
	hash := sha256.Sum256([]byte(verifier))
	c, e := s.PrepareConsent(ctx, p, "prepare:"+key, op.ConsentInput{ClientID: a.ID, RedirectURI: a.RedirectURIs[0], State: "state-bound-to-test-browser", Scopes: scopes, Challenge: base64.RawURLEncoding.EncodeToString(hash[:]), Method: "S256"})
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.Decide(ctx, p, c.ID, "decide:"+key, op.ConsentDecision{Decision: "approve", Scopes: scopes})
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(result.RedirectURI)
	if e != nil || u.Query().Get("state") != "state-bound-to-test-browser" || u.Query().Get("iss") != s.Issuer {
		t.Fatal("unbound authorization result", e)
	}
	return c, u.Query().Get("code"), verifier
}
func exchange(t *testing.T, s *op.Service, a op.Application, code, verifier, secret string) op.Token {
	t.Helper()
	v, e := s.Exchange(ctx, op.TokenInput{GrantType: "authorization_code", ClientID: a.ID, RedirectURI: a.RedirectURIs[0], Code: code, Verifier: verifier, ClientSecret: secret})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func tokenFor(t *testing.T, s *op.Service, p op.Principal, a op.Application, key string, scopes []string) op.Token {
	_, code, verifier := consent(t, s, p, a, key, scopes)
	return exchange(t, s, a, code, verifier, "")
}
func count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if e := db.QueryRow(q, args...).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestApplicationApprovalAndPerScopeAuthorization(t *testing.T) {
	x := setup(t)
	s := x.s
	a := apply(t, s, dev, "create", []string{"profile", "qq_binding", "student_status"}, "confidential")
	if _, e := s.PrepareConsent(ctx, alice, "pending", op.ConsentInput{ClientID: a.ID, RedirectURI: a.RedirectURIs[0], State: strings.Repeat("s", 16), Scopes: []string{"profile"}, Challenge: strings.Repeat("A", 43), Method: "S256"}); !errors.Is(e, op.ErrForbidden) {
		t.Fatal(e)
	}
	if _, e := s.Review(ctx, dev, a.ID, "not-admin", op.ReviewInput{Revision: a.Revision, Decision: "suspend"}); !errors.Is(e, op.ErrForbidden) {
		t.Fatal(e)
	}
	if _, e := s.Application(ctx, bob, a.ID); !errors.Is(e, op.ErrNotFound) {
		t.Fatal(e)
	}
	a = approve(t, s, a, []string{"profile", "qq_binding"}, 100)
	if _, e := s.PrepareConsent(ctx, alice, "not-approved", op.ConsentInput{ClientID: a.ID, RedirectURI: a.RedirectURIs[0], State: strings.Repeat("s", 16), Scopes: []string{"student_status"}, Challenge: strings.Repeat("A", 43), Method: "S256"}); !errors.Is(e, op.ErrForbidden) {
		t.Fatal(e)
	}
	for _, redirect := range []string{"https://client.example/callback/", "https://client.example/callback?attack=1", "https://evil.example/callback"} {
		if _, e := s.PrepareConsent(ctx, alice, "bad-redirect:"+redirect, op.ConsentInput{ClientID: a.ID, RedirectURI: redirect, State: strings.Repeat("s", 16), Scopes: []string{"profile"}, Challenge: strings.Repeat("A", 43), Method: "S256"}); !errors.Is(e, op.ErrForbidden) {
			t.Fatal(e)
		}
	}
	cr, e := s.RotateCredential(ctx, dev, a.ID, "secret", 0)
	if e != nil || !cr.Retrievable || cr.Secret == "" {
		t.Fatal(cr, e)
	}
	again, e := s.RotateCredential(ctx, dev, a.ID, "secret", 0)
	if e != nil || again.Retrievable || again.Secret != "" {
		t.Fatal(again, e)
	}
	c, code, verifier := consent(t, s, alice, a, "one", []string{"profile"})
	if _, e = s.Consent(ctx, bob, c.ID); !errors.Is(e, op.ErrNotFound) {
		t.Fatal(e)
	}
	if _, e = s.Exchange(ctx, op.TokenInput{GrantType: "authorization_code", ClientID: a.ID, RedirectURI: a.RedirectURIs[0], Code: code, Verifier: verifier}); !errors.Is(e, op.ErrClient) {
		t.Fatal(e)
	}
	if _, e = s.Exchange(ctx, op.TokenInput{GrantType: "authorization_code", ClientID: a.ID, RedirectURI: a.RedirectURIs[0], Code: code, Verifier: strings.Repeat("b", 43), ClientSecret: cr.Secret}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	token := exchange(t, s, a, code, verifier, cr.Secret)
	_, qqCode, qqVerifier := consent(t, s, bob, a, "qq-read", []string{"qq_binding"})
	qqToken := exchange(t, s, a, qqCode, qqVerifier, cr.Secret)
	qqData, qqErr := s.Read(ctx, qqToken.AccessToken, "qq_binding", op.Query{})
	if qqErr != nil || qqData.QQBinding == nil || !qqData.QQBinding.Bound || qqData.QQBinding.Number != "123456" || qqData.Profile != nil {
		t.Fatal(qqData, qqErr)
	}

	data, e := s.Read(ctx, token.AccessToken, "profile", op.Query{})
	if e != nil || data.Profile == nil || data.Profile.Nickname != "alice" || data.QQBinding != nil || data.Subject != token.Subject {
		t.Fatal(data, e)
	}
	before := x.source.calls.Load()
	if _, e = s.Read(ctx, token.AccessToken, "qq_binding", op.Query{}); !errors.Is(e, op.ErrForbidden) || x.source.calls.Load() != before {
		t.Fatal(e)
	}
	// Consent retry returns the same code but never stores a recoverable plaintext credential.
	result, e := s.Decide(ctx, alice, c.ID, "decide:one", op.ConsentDecision{Decision: "approve", Scopes: []string{"profile"}})
	if e != nil || !strings.Contains(result.RedirectURI, code) {
		t.Fatal(result, e)
	}
	for _, secret := range []string{cr.Secret, code, token.AccessToken} {
		if n := count(t, x.db, `SELECT count(*) FROM open_platform.requests WHERE strpos(result::text,$1)>0`, secret); n != 0 {
			t.Fatal("plaintext secret in replay")
		}
		if n := count(t, x.db, `SELECT count(*) FROM open_platform.consents WHERE strpos(document::text,$1)>0`, secret); n != 0 {
			t.Fatal("plaintext secret in consent")
		}
	}
	changed := op.ConsentDecision{Decision: "approve", Scopes: []string{"profile", "qq_binding"}}
	if _, e = s.Decide(ctx, alice, c.ID, "decide:one", changed); !errors.Is(e, op.ErrConflict) {
		t.Fatal(e)
	}
	// One issuance under concurrent exchange; single-use survives multiple connections.
	_, code2, v2 := consent(t, s, bob, a, "concurrent", []string{"qq_binding"})
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.Exchange(ctx, op.TokenInput{GrantType: "authorization_code", ClientID: a.ID, RedirectURI: a.RedirectURIs[0], Code: code2, Verifier: v2, ClientSecret: cr.Secret})
			if e == nil {
				success.Add(1)
			} else if !errors.Is(e, op.ErrUnauthenticated) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal(success.Load())
	}
	// Audit failure rolls back the business record and idempotency result together.
	if _, e = x.db.Exec(`ALTER TABLE open_platform.events ADD CONSTRAINT reject_application CHECK(kind<>'application:') NOT VALID`); e != nil {
		t.Fatal(e)
	}
	_, e = s.Apply(ctx, dev, "", "rollback", op.ApplicationInput{Name: "Rollback", Purpose: "test", RedirectURIs: []string{"https://x.example/cb"}, RequestedScopes: []string{"profile"}, ClientType: "public"})
	if e == nil {
		t.Fatal("audit failure ignored")
	}
	if count(t, x.db, `SELECT count(*) FROM open_platform.apps WHERE document->>'name'='Rollback'`) != 0 || count(t, x.db, `SELECT count(*) FROM open_platform.requests WHERE key='rollback'`) != 0 {
		t.Fatal("partial transaction")
	}
}
func TestRevocationExpiryQuotaAndClosureFence(t *testing.T) {
	x := setup(t)
	s := x.s
	a := approve(t, s, apply(t, s, dev, "app", []string{"profile", "student_status"}, "public"), []string{"profile", "student_status"}, 2)
	token := tokenFor(t, s, alice, a, "initial", []string{"profile", "student_status"})
	for range 2 {
		if _, e := s.Read(ctx, token.AccessToken, "profile", op.Query{}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.Read(ctx, token.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrQuota) {
		t.Fatal(e)
	}
	gs, e := s.Grants(ctx, alice, "", 50)
	if e != nil || len(gs.Items) != 1 {
		t.Fatal(gs, e)
	}
	g := gs.Items[0]
	if _, e = s.Revoke(ctx, bob, g.ID, "other", op.RevokeInput{Revision: g.Revision, Scopes: []string{"profile"}}); !errors.Is(e, op.ErrNotFound) {
		t.Fatal(e)
	}
	for range 2 {
		g, e = s.Revoke(ctx, alice, g.ID, "remove-profile", op.RevokeInput{Revision: gs.Items[0].Revision, Scopes: []string{"profile"}})
		if e != nil || len(g.Scopes) != 1 {
			t.Fatal(g, e)
		}
	}
	if _, e = s.Read(ctx, token.AccessToken, "student_status", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	notices, e := s.Notices(ctx, dev, a.ID, "", "", 1)
	if e != nil || len(notices.Items) != 1 || notices.Items[0].SeenAt == nil || notices.Items[0].Acknowledgement != "" {
		t.Fatal(notices, e)
	}
	n, e := s.Acknowledge(ctx, dev, a.ID, "", notices.Items[0].ID, "ack", op.Acknowledgement{Status: "retention_exception", Note: "Synthetic statutory retention reason"})
	if e != nil || n.Acknowledgement != "retention_exception" {
		t.Fatal(n, e)
	}
	if _, e = s.Acknowledge(ctx, dev, a.ID, "", n.ID, "missing-reason", op.Acknowledgement{Status: "retention_exception"}); !errors.Is(e, op.ErrInput) {
		t.Fatal(e)
	}
	// New approval invalidates every previous grant even before the worker creates notices.
	a = approve(t, s, a, []string{"profile", "student_status"}, 100)
	token = tokenFor(t, s, alice, a, "new-epoch", []string{"profile"})
	x.source.entered = make(chan struct{})
	x.source.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, e := s.Read(ctx, token.AccessToken, "profile", op.Query{}); done <- e }()
	<-x.source.entered
	gs, e = s.Grants(ctx, alice, "", 50)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Revoke(ctx, alice, gs.Items[0].ID, "race", op.RevokeInput{Revision: gs.Items[0].Revision, Scopes: []string{"profile"}})
	if e != nil {
		t.Fatal(e)
	}
	close(x.source.release)
	if e = <-done; !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal("in-flight result escaped", e)
	}
	x.source.entered = nil
	x.source.release = nil
	token = tokenFor(t, s, bob, a, "expires", []string{"profile"})
	x.clock.Add(601)
	if _, e = s.Read(ctx, token.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	if _, e = s.Work(ctx, 100); e != nil {
		t.Fatal(e)
	}
	token = tokenFor(t, s, alice, a, "developer-closure", []string{"profile"})
	if e = s.CloseAccount(ctx, dev.Owner, "closure-one"); e != nil {
		t.Fatal(e)
	}
	if e = s.CloseAccount(ctx, dev.Owner, "closure-one"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Read(ctx, token.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	latest, e := s.Application(ctx, admin, a.ID)
	if e != nil || latest.State != "suspended" {
		t.Fatal(latest, e)
	}
	if _, e = s.Review(ctx, admin, a.ID, "cannot-reenable", op.ReviewInput{Revision: latest.Revision, Decision: "approve", ApprovedScopes: []string{"profile"}, Policy: a.Policy}); !errors.Is(e, op.ErrForbidden) {
		t.Fatal(e)
	}
	if _, e = s.Work(ctx, 1); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Work(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if count(t, x.db, `SELECT count(*) FROM open_platform.grants WHERE state='active'`) != 0 {
		t.Fatal("closure notice progress incomplete")
	}
	if _, e = s.PrepareConsent(ctx, dev, "closed-consent", op.ConsentInput{ClientID: a.ID, RedirectURI: a.RedirectURIs[0], State: strings.Repeat("s", 16), Scopes: []string{"profile"}, Challenge: strings.Repeat("A", 43), Method: "S256"}); !errors.Is(e, op.ErrForbidden) {
		t.Fatal(e)
	}
}
func TestHTTPRejectsForgedOwnersAndUsesOAuthExchange(t *testing.T) {
	x := setup(t)
	s := x.s
	h := httpapi.Handler{Service: s, Authenticate: func(r *http.Request) (op.Principal, error) {
		v := r.Header.Get("Authorization")
		if v == "Bearer session-alice" {
			return alice, nil
		}
		return op.Principal{}, op.ErrUnauthenticated
	}}
	call := func(method, path, auth, key, body, content string, status int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v1/open-platform"+path, strings.NewReader(body))
		r.Header.Set("Authorization", auth)
		r.Header.Set("Content-Type", content)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable response")
		}
		return w
	}
	call("GET", "/apps", "", "", "", "", 401)
	call("POST", "/apps", "Bearer session-alice", "forged", `{"name":"X","purpose":"test","redirect_uris":["https://x.example/cb"],"requested_scopes":["profile"],"client_type":"public","owner":"bob"}`, "application/json", 400)
	call("GET", "/apps?limit=101", "Bearer session-alice", "", "", "", 400)
	a := approve(t, s, apply(t, s, dev, "app", []string{"profile"}, "public"), []string{"profile"}, 100)
	_, code, v := consent(t, s, alice, a, "http", []string{"profile"})
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {a.ID}, "redirect_uri": {a.RedirectURIs[0]}, "code": {code}, "code_verifier": {v}}.Encode()
	w := call("POST", "/token", "", "", form, "application/x-www-form-urlencoded", 200)
	var token op.Token
	if json.Unmarshal(w.Body.Bytes(), &token) != nil {
		t.Fatal("token JSON")
	}
	call("GET", "/data/profile?owner=bob", "Bearer "+token.AccessToken, "", "", "", 400)
	call("GET", "/data/profile", "Bearer session-alice", "", "", "", 401)
	w = call("GET", "/data/profile", "Bearer "+token.AccessToken, "", "", "", 200)
	if strings.Contains(w.Body.String(), "qq_binding") {
		t.Fatal("scope projection leak")
	}
	call("POST", "/token", "", "", form, "application/x-www-form-urlencoded", 400)
	call("GET", "/data/profile", "Bearer "+token.AccessToken, "", "", "", 401)
}

func TestSuspensionConsentBindingAndConcurrentQuota(t *testing.T) {
	x := setup(t)
	s := x.s
	a := approve(t, s, apply(t, s, dev, "app", []string{"profile", "student_status"}, "public"), []string{"profile", "student_status"}, 10)
	hash := sha256.Sum256([]byte(strings.Repeat("a", 43)))
	in := op.ConsentInput{ClientID: a.ID, RedirectURI: a.RedirectURIs[0], State: strings.Repeat("x", 20), Scopes: []string{"profile"}, Challenge: base64.RawURLEncoding.EncodeToString(hash[:]), Method: "S256"}
	c, e := s.PrepareConsent(ctx, alice, "bound", in)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Decide(ctx, alice, c.ID, "widen", op.ConsentDecision{Decision: "approve", Scopes: []string{"student_status"}}); !errors.Is(e, op.ErrForbidden) {
		t.Fatal(e)
	}
	denied, e := s.Decide(ctx, alice, c.ID, "deny", op.ConsentDecision{Decision: "deny", Scopes: []string{}})
	if e != nil || !strings.Contains(denied.RedirectURI, "access_denied") {
		t.Fatal(denied, e)
	}
	if count(t, x.db, `SELECT count(*) FROM open_platform.grants`) != 0 {
		t.Fatal("deny granted access")
	}
	token := tokenFor(t, s, alice, a, "quota", []string{"profile"})
	var ok, limited atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.Read(ctx, token.AccessToken, "profile", op.Query{})
			if e == nil {
				ok.Add(1)
			} else if errors.Is(e, op.ErrQuota) {
				limited.Add(1)
			} else {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 10 || limited.Load() != 10 || x.source.calls.Load() != 10 {
		t.Fatal(ok.Load(), limited.Load(), x.source.calls.Load())
	}
	suspended, e := s.Review(ctx, admin, a.ID, "suspend", op.ReviewInput{Revision: a.Revision, Decision: "suspend", ApprovedScopes: []string{}, Note: "Synthetic suspension"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Read(ctx, token.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	a = approve(t, s, suspended, []string{"profile", "student_status"}, 100)
	if _, e = s.Read(ctx, token.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal("old token resumed", e)
	}
	token = tokenFor(t, s, alice, a, "reconsent", []string{"profile"})
	other := tokenFor(t, s, bob, a, "bob", []string{"profile"})
	if e = s.CloseAccount(ctx, alice.Owner, "own-closure"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Read(ctx, token.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	if _, e = s.Read(ctx, other.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal("unrelated grant revoked", e)
	}
	if _, e = s.Work(ctx, 100); e != nil {
		t.Fatal(e)
	}
	first, e := s.Notices(ctx, dev, a.ID, "", "", 1)
	if e != nil || first.Next == "" {
		t.Fatal(first, e)
	}
	second, e := s.Notices(ctx, dev, a.ID, "", first.Next, 100)
	if e != nil || len(second.Items) == 0 || second.Items[0].Sequence <= first.Items[0].Sequence {
		t.Fatal(second, e)
	}
	before := count(t, x.db, `SELECT count(*) FROM open_platform.notices`)
	if _, e = s.Work(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if count(t, x.db, `SELECT count(*) FROM open_platform.notices`) != before {
		t.Fatal("duplicate notices")
	}
	s.Source = nil
	if _, e = s.Read(ctx, other.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnavailable) {
		t.Fatal(e)
	}
	_, code, verifier := consent(t, s, bob, a, "old-code", []string{"profile"})
	x.clock.Add(61)
	if _, e = s.Exchange(ctx, op.TokenInput{GrantType: "authorization_code", ClientID: a.ID, RedirectURI: a.RedirectURIs[0], Code: code, Verifier: verifier}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
}
