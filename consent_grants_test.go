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
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConsentSummaryComparisonAndIncrementalMergeMode(t *testing.T) {
	x := setup(t)
	s := x.s
	app := apply(t, s, dev, "campus-tool", []string{"profile", "student_status", "qq_binding_status", "schools"}, "confidential")
	app = approve(t, s, app, []string{"profile", "student_status", "qq_binding_status"}, 100)
	cr, e := s.RotateCredential(ctx, dev, app.ID, "rot-1", 0)
	if e != nil {
		t.Fatal(e)
	}

	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	prepared, e := s.PrepareConsent(ctx, alice, "prep-1", op.ConsentInput{
		ClientID:    app.ID,
		RedirectURI: app.RedirectURIs[0],
		State:       strings.Repeat("s", 16),
		Scopes:      []string{"profile", "student_status"},
		Challenge:   challenge,
		Method:      "S256",
	})
	if e != nil {
		t.Fatal(e)
	}
	rawConsent, e := json.Marshal(prepared)
	if e != nil {
		t.Fatal(e)
	}
	for _, hidden := range []string{"credential_revision", "approved_scopes", "daily_quota", "redirect_uris"} {
		if strings.Contains(string(rawConsent), hidden) {
			t.Fatalf("consent leaked management field %s: %s", hidden, string(rawConsent))
		}
	}
	if prepared.Application.ID != app.ID || prepared.Application.GrantSeconds != app.Policy.GrantSeconds || len(prepared.ActiveGrantedScopes) != 0 || prepared.ActiveGrantExpiresAt != nil {
		t.Fatalf("unexpected initial consent view: %+v", prepared)
	}
	if !strings.Contains(string(rawConsent), `"active_granted_scopes":[]`) {
		t.Fatalf("expected non-null empty active_granted_scopes: %s", string(rawConsent))
	}

	if _, e = s.Decide(ctx, alice, prepared.ID, "bad-mode", op.ConsentDecision{Decision: "approve", Scopes: []string{"profile"}, Mode: "invalid"}); !errors.Is(e, op.ErrInput) {
		t.Fatalf("expected invalid mode error, got %v", e)
	}
	res1, e := s.Decide(ctx, alice, prepared.ID, "dec-1", op.ConsentDecision{Decision: "approve", Scopes: []string{"profile", "student_status"}})
	if e != nil {
		t.Fatal(e)
	}
	_ = res1

	// Re-consent requesting only qq_binding_status; default merge preserves profile and student_status.
	x.clock.Add(30)
	prepared2, e := s.PrepareConsent(ctx, alice, "prep-2", op.ConsentInput{
		ClientID:    app.ID,
		RedirectURI: app.RedirectURIs[0],
		State:       strings.Repeat("t", 16),
		Scopes:      []string{"qq_binding_status"},
		Challenge:   challenge,
		Method:      "S256",
	})
	if e != nil {
		t.Fatal(e)
	}
	fetched2, e := s.Consent(ctx, alice, prepared2.ID)
	if e != nil {
		t.Fatal(e)
	}
	wantActive := []string{"profile", "student_status"}
	if !reflect.DeepEqual(prepared2.ActiveGrantedScopes, wantActive) || !reflect.DeepEqual(fetched2.ActiveGrantedScopes, wantActive) || fetched2.ActiveGrantExpiresAt == nil {
		t.Fatalf("unexpected active grant comparison: prepared=%+v fetched=%+v", prepared2, fetched2)
	}
	res2, e := s.Decide(ctx, alice, prepared2.ID, "dec-2", op.ConsentDecision{Decision: "approve", Scopes: []string{"qq_binding_status"}})
	if e != nil {
		t.Fatal(e)
	}
	code2 := mustQueryParam(t, res2.RedirectURI, "code")
	tok2 := exchange(t, s, app, code2, verifier, cr.Secret)
	for _, sc := range []string{"profile", "student_status", "qq_binding_status"} {
		if _, e = s.Read(ctx, tok2.AccessToken, sc, op.Query{}); e != nil {
			t.Fatalf("merged scope %s unreadable: %v", sc, e)
		}
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.notices WHERE app_id=$1`, app.ID); n != 0 {
		t.Fatalf("merge mode emitted unexpected withdrawal notices: %d", n)
	}

	// Replace mode explicitly drops unselected scopes and notifies only removed scopes.
	prepared3, e := s.PrepareConsent(ctx, alice, "prep-3", op.ConsentInput{
		ClientID:    app.ID,
		RedirectURI: app.RedirectURIs[0],
		State:       strings.Repeat("u", 16),
		Scopes:      []string{"profile"},
		Challenge:   challenge,
		Method:      "S256",
	})
	if e != nil {
		t.Fatal(e)
	}
	res3, e := s.Decide(ctx, alice, prepared3.ID, "dec-3", op.ConsentDecision{Decision: "approve", Scopes: []string{"profile", "student_status"}, Mode: "replace"})
	if e != nil {
		t.Fatal(e)
	}
	code3 := mustQueryParam(t, res3.RedirectURI, "code")
	tok3 := exchange(t, s, app, code3, verifier, cr.Secret)
	if _, e = s.Read(ctx, tok3.AccessToken, "qq_binding_status", op.Query{}); !errors.Is(e, op.ErrForbidden) {
		t.Fatalf("expected replaced scope to be forbidden, got %v", e)
	}
	notices, e := s.Notices(ctx, dev, app.ID, "", "", 10)
	if e != nil || len(notices.Items) != 1 || notices.Items[0].Reason != "consent_changed" || !reflect.DeepEqual(notices.Items[0].Scopes, []string{"qq_binding_status"}) {
		t.Fatalf("unexpected replace notice: %+v err=%v", notices, e)
	}

	// Expired grant is not treated as active in consent view or resurrected by merge.
	x.clock.Add(601)
	prepared4, e := s.PrepareConsent(ctx, alice, "prep-4", op.ConsentInput{
		ClientID:    app.ID,
		RedirectURI: app.RedirectURIs[0],
		State:       strings.Repeat("w", 16),
		Scopes:      []string{"profile"},
		Challenge:   challenge,
		Method:      "S256",
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(prepared4.ActiveGrantedScopes) != 0 || prepared4.ActiveGrantExpiresAt != nil {
		t.Fatalf("expired grant must not appear active: %+v", prepared4)
	}
	res4, e := s.Decide(ctx, alice, prepared4.ID, "dec-4", op.ConsentDecision{Decision: "approve", Scopes: []string{"profile"}, Mode: "merge"})
	if e != nil {
		t.Fatal(e)
	}
	code4 := mustQueryParam(t, res4.RedirectURI, "code")
	tok4 := exchange(t, s, app, code4, verifier, cr.Secret)
	if _, e = s.Read(ctx, tok4.AccessToken, "student_status", op.Query{}); !errors.Is(e, op.ErrForbidden) {
		t.Fatalf("expired scope resurrected by merge: %v", e)
	}
	noticesAfter, e := s.Notices(ctx, dev, app.ID, "", fmt.Sprint(notices.Items[0].Sequence), 10)
	if e != nil || len(noticesAfter.Items) != 1 || noticesAfter.Items[0].Reason != "expired" {
		t.Fatalf("expected expired notice for prior expired grant, got %+v err=%v", noticesAfter, e)
	}
}

func TestGrantsLifecycleMetadataFilteringOrderingAndWholeRevoke(t *testing.T) {
	x := setup(t)
	s := x.s
	devClosed := op.Principal{Owner: "developer-closed"}

	appRevoked := approve(t, s, apply(t, s, dev, "app-revoked", []string{"profile", "student_status"}, "public"), []string{"profile", "student_status"}, 100)
	appExpired := approve(t, s, apply(t, s, dev, "app-expired", []string{"profile"}, "public"), []string{"profile"}, 100)
	appSuspended := approve(t, s, apply(t, s, dev, "app-suspended", []string{"profile"}, "public"), []string{"profile"}, 100)
	appClosed := approve(t, s, apply(t, s, devClosed, "app-closed", []string{"profile"}, "public"), []string{"profile"}, 100)
	appActiveOld := approve(t, s, apply(t, s, dev, "app-active-old", []string{"profile"}, "public"), []string{"profile"}, 100)
	appActiveNew := approve(t, s, apply(t, s, dev, "app-active-new", []string{"profile", "student_status"}, "public"), []string{"profile", "student_status"}, 100)

	// 1. Expired grant (grant_seconds = 600, advance past it later).
	_ = tokenFor(t, s, alice, appExpired, "g-expired", []string{"profile"})
	x.clock.Add(700)

	// 2. User-revoked whole grant via RevokeAll.
	_ = tokenFor(t, s, alice, appRevoked, "g-revoked", []string{"profile", "student_status"})
	x.clock.Add(10)
	activeNow, e := s.ListGrants(ctx, alice, "active", "", 50)
	if e != nil || len(activeNow.Items) != 1 {
		t.Fatalf("expected 1 active grant, got %+v err=%v", activeNow, e)
	}
	if _, e = s.Revoke(ctx, alice, activeNow.Items[0].ID, "empty-scopes", op.RevokeInput{Revision: activeNow.Items[0].Revision, Scopes: []string{}}); !errors.Is(e, op.ErrInput) {
		t.Fatalf("expected explicit empty scopes to fail with ErrInput, got %v", e)
	}
	if _, e = s.Revoke(ctx, alice, activeNow.Items[0].ID, "both-set", op.RevokeInput{Revision: activeNow.Items[0].Revision, Scopes: []string{"profile"}, RevokeAll: true}); !errors.Is(e, op.ErrInput) {
		t.Fatalf("expected revoke_all + scopes conflict to fail with ErrInput, got %v", e)
	}
	revokedGrant, e := s.Revoke(ctx, alice, activeNow.Items[0].ID, "whole-revoke", op.RevokeInput{Revision: activeNow.Items[0].Revision, RevokeAll: true})
	if e != nil || revokedGrant.State != "revoked" || revokedGrant.TerminationReason != "user_revoked" || len(revokedGrant.Scopes) != 0 {
		t.Fatalf("unexpected whole revoke result: %+v err=%v", revokedGrant, e)
	}
	if _, e = s.Revoke(ctx, alice, revokedGrant.ID, "repeat-revoke", op.RevokeInput{Revision: revokedGrant.Revision, RevokeAll: true}); !errors.Is(e, op.ErrConflict) {
		t.Fatalf("expected revoking inactive grant to return ErrConflict, got %v", e)
	}

	// 3. Suspended application grant.
	x.clock.Add(10)
	_ = tokenFor(t, s, alice, appSuspended, "g-suspended", []string{"profile"})
	x.clock.Add(5)
	if _, e = s.Review(ctx, admin, appSuspended.ID, "sus-app", op.ReviewInput{Revision: appSuspended.Revision, Decision: "suspend", ApprovedScopes: []string{}, Note: "Suspended for test"}); e != nil {
		t.Fatal(e)
	}

	// 4. Closed developer account grant.
	x.clock.Add(10)
	_ = tokenFor(t, s, alice, appClosed, "g-closed", []string{"profile"})
	x.clock.Add(5)
	if e = s.CloseAccount(ctx, devClosed.Owner, "close-dev"); e != nil {
		t.Fatal(e)
	}

	// 5. Two active grants with data reads and renewal preserving granted_at.
	x.clock.Add(10)
	tokOld := tokenFor(t, s, alice, appActiveOld, "g-active-old", []string{"profile"})
	x.clock.Add(10)
	grantedAtStart := time.Unix(x.clock.Load(), 0).UTC()
	tokNew := tokenFor(t, s, alice, appActiveNew, "g-active-new", []string{"profile"})

	// Verify last_data_read_at throttling and preservation of updated_at.
	x.clock.Add(5)
	firstReadAt := time.Unix(x.clock.Load(), 0).UTC()
	if _, e = s.Read(ctx, tokNew.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal(e)
	}
	x.clock.Add(20)
	if _, e = s.Read(ctx, tokNew.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal(e)
	}
	pageCheck, e := s.ListGrants(ctx, alice, "active", "", 10)
	if e != nil || len(pageCheck.Items) != 2 {
		t.Fatalf("unexpected active grants: %+v err=%v", pageCheck, e)
	}
	if pageCheck.Items[0].AppID != appActiveNew.ID || pageCheck.Items[0].LastDataReadAt == nil || !pageCheck.Items[0].LastDataReadAt.Equal(firstReadAt) {
		t.Fatalf("expected throttled firstReadAt %v, got %+v", firstReadAt, pageCheck.Items[0])
	}
	if !pageCheck.Items[0].GrantedAt.Equal(grantedAtStart) || !pageCheck.Items[0].UpdatedAt.Equal(grantedAtStart) {
		t.Fatalf("read must not mutate granted_at/updated_at: %+v", pageCheck.Items[0])
	}
	x.clock.Add(65)
	laterReadAt := time.Unix(x.clock.Load(), 0).UTC()
	if _, e = s.Read(ctx, tokNew.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal(e)
	}
	// Re-consent to appActiveNew; granted_at stays grantedAtStart while updated_at advances.
	x.clock.Add(5)
	renewedAt := time.Unix(x.clock.Load(), 0).UTC()
	_ = tokenFor(t, s, alice, appActiveNew, "g-active-new-2", []string{"student_status"})
	_ = tokOld

	// Check termination reasons both before and after Work() materializes notices.
	for round := range 2 {
		if round == 1 {
			if _, e = s.Work(ctx, 100); e != nil {
				t.Fatal(e)
			}
		}
		var all []op.Grant
		cursor := ""
		for {
			p, err := s.ListGrants(ctx, alice, "", cursor, 2)
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, p.Items...)
			if p.Next == "" {
				break
			}
			cursor = p.Next
		}
		if len(all) != 6 {
			t.Fatalf("round %d: expected 6 grants across pages, got %d: %+v", round, len(all), all)
		}
		if all[0].AppID != appActiveNew.ID || all[0].State != "active" || all[0].TerminationReason != "" || !all[0].GrantedAt.Equal(grantedAtStart) || !all[0].UpdatedAt.Equal(renewedAt) || all[0].LastDataReadAt == nil || !all[0].LastDataReadAt.Equal(laterReadAt) {
			t.Fatalf("round %d: unexpected first active grant: %+v", round, all[0])
		}
		if all[1].AppID != appActiveOld.ID || all[1].State != "active" || all[1].TerminationReason != "" || all[1].LastDataReadAt != nil {
			t.Fatalf("round %d: unexpected second active grant: %+v", round, all[1])
		}
		reasons := map[string]string{}
		for _, g := range all[2:] {
			if g.State != "revoked" {
				t.Fatalf("round %d: expected revoked state after active group: %+v", round, g)
			}
			reasons[g.AppID] = g.TerminationReason
		}
		wantReasons := map[string]string{
			appRevoked.ID:   "user_revoked",
			appExpired.ID:   "expired",
			appSuspended.ID: "application_changed",
			appClosed.ID:    "account_closed",
		}
		if !reflect.DeepEqual(reasons, wantReasons) {
			t.Fatalf("round %d: termination reasons mismatch: got %+v want %+v", round, reasons, wantReasons)
		}
	}

	// Verify HTTP ?state=active|revoked and omitted-scopes whole-grant revoke.
	h := httpapi.Handler{Service: s, Authenticate: func(r *http.Request) (op.Principal, error) { return alice, nil }}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/open-platform/grants?state=revoked&limit=10", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /grants?state=revoked failed: %d %s", w.Code, w.Body.String())
	}
	var revokedPage op.Page[op.Grant]
	if e = json.Unmarshal(w.Body.Bytes(), &revokedPage); e != nil || len(revokedPage.Items) != 4 {
		t.Fatalf("unexpected HTTP revoked grants page: %+v err=%v", revokedPage, e)
	}
	badReq := httptest.NewRequest(http.MethodGet, "/api/v1/open-platform/grants?state=unknown", nil)
	badW := httptest.NewRecorder()
	h.ServeHTTP(badW, badReq)
	if badW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid state filter, got %d", badW.Code)
	}

	// Whole-grant revoke via HTTP omitting scopes field.
	activeOnly, e := s.ListGrants(ctx, alice, "active", "", 10)
	if e != nil || len(activeOnly.Items) != 2 {
		t.Fatal(activeOnly, e)
	}
	revReq := httptest.NewRequest(http.MethodPost, "/api/v1/open-platform/grants/"+activeOnly.Items[1].ID+"/revoke", strings.NewReader(fmt.Sprintf(`{"revision":%d}`, activeOnly.Items[1].Revision)))
	revReq.Header.Set("Content-Type", "application/json")
	revReq.Header.Set("Idempotency-Key", "http-omit-scopes")
	revW := httptest.NewRecorder()
	h.ServeHTTP(revW, revReq)
	if revW.Code != http.StatusOK {
		t.Fatalf("POST /grants/{id}/revoke without scopes failed: %d %s", revW.Code, revW.Body.String())
	}
	var httpRevoked op.Grant
	if e = json.Unmarshal(revW.Body.Bytes(), &httpRevoked); e != nil || httpRevoked.State != "revoked" || httpRevoked.TerminationReason != "user_revoked" {
		t.Fatalf("unexpected HTTP whole revoke grant: %+v err=%v", httpRevoked, e)
	}
}

func mustQueryParam(t *testing.T, rawURL, key string) string {
	t.Helper()
	parts := strings.SplitN(rawURL, "?", 2)
	if len(parts) != 2 {
		t.Fatalf("missing query string in %s", rawURL)
	}
	for _, kv := range strings.Split(parts[1], "&") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k == key {
			return v
		}
	}
	t.Fatalf("missing query param %s in %s", key, rawURL)
	return ""
}
