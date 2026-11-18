package openplatform_test

import (
	"encoding/json"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminApplicationFilteringOrderingAndDetailStats(t *testing.T) {
	x := setup(t)
	s := x.s
	devTwo := op.Principal{Owner: "developer-two"}

	createdT1 := time.Unix(x.clock.Load(), 0).UTC()
	app1 := apply(t, s, dev, "app-1", []string{"profile", "student_status"}, "public")

	x.clock.Add(10)
	app2 := apply(t, s, dev, "app-2", []string{"profile"}, "confidential")
	x.clock.Add(5)
	if _, e := s.Review(ctx, admin, app2.ID, "chg-2", op.ReviewInput{Revision: app2.Revision, Decision: "changes_requested", ApprovedScopes: []string{}, Note: "Clarify callback domain"}); e != nil {
		t.Fatal(e)
	}

	x.clock.Add(10)
	app3 := apply(t, s, devTwo, "app-3", []string{"profile"}, "public")
	x.clock.Add(5)
	app3 = approve(t, s, app3, []string{"profile"}, 100)
	x.clock.Add(5)
	if _, e := s.Review(ctx, admin, app3.ID, "sus-3", op.ReviewInput{Revision: app3.Revision, Decision: "suspend", ApprovedScopes: []string{}, Note: "Suspended for audit"}); e != nil {
		t.Fatal(e)
	}

	x.clock.Add(10)
	app4 := apply(t, s, devTwo, "app-4", []string{"profile"}, "public")

	// Approve app1 last so its updated_at is newest, while created_at stays createdT1.
	x.clock.Add(20)
	reviewAt := time.Unix(x.clock.Load(), 0).UTC()
	app1 = approve(t, s, app1, []string{"profile", "student_status"}, 100)

	// Grant app1 to alice and bob; verify active_grants reflects live valid grants.
	_ = tokenFor(t, s, alice, app1, "g-alice", []string{"profile", "student_status"})
	_ = tokenFor(t, s, bob, app1, "g-bob", []string{"profile"})

	detail, e := s.AdminApplication(ctx, admin, app1.ID)
	if e != nil {
		t.Fatal(e)
	}
	if detail.Owner != dev.Owner || detail.ActiveGrants != 2 || detail.ReviewedBy != admin.Owner || detail.ReviewedAt == nil || !detail.ReviewedAt.Equal(reviewAt) || !detail.CreatedAt.Equal(createdT1) || !detail.UpdatedAt.Equal(reviewAt) {
		t.Fatalf("unexpected admin application detail: %+v", detail)
	}
	pendingDetail, e := s.AdminApplication(ctx, admin, app4.ID)
	if e != nil {
		t.Fatal(e)
	}
	if pendingDetail.Owner != devTwo.Owner || pendingDetail.ReviewedBy != "" || pendingDetail.ReviewedAt != nil || pendingDetail.ActiveGrants != 0 {
		t.Fatalf("unexpected unreviewed admin application detail: %+v", pendingDetail)
	}

	// Revoking bob's grant reduces active_grants to 1 immediately.
	bobGrants, e := s.Grants(ctx, bob, "", 10)
	if e != nil || len(bobGrants.Items) != 1 {
		t.Fatal(bobGrants, e)
	}
	if _, e = s.Revoke(ctx, bob, bobGrants.Items[0].ID, "rev-bob", op.RevokeInput{Revision: bobGrants.Items[0].Revision, Scopes: []string{"profile"}}); e != nil {
		t.Fatal(e)
	}
	detailAfterRevoke, e := s.AdminApplication(ctx, admin, app1.ID)
	if e != nil || detailAfterRevoke.ActiveGrants != 1 {
		t.Fatalf("expected active_grants=1 after bob revoked, got %+v err=%v", detailAfterRevoke, e)
	}

	// Authorization boundaries for non-admin and unauthenticated callers.
	if _, e = s.AdminApplications(ctx, dev, op.AdminAppFilter{}); !errors.Is(e, op.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for developer listing admin apps, got %v", e)
	}
	if _, e = s.AdminApplication(ctx, dev, app1.ID); !errors.Is(e, op.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for developer reading admin app detail, got %v", e)
	}
	if _, e = s.AdminApplication(ctx, admin, "missing-app-id"); !errors.Is(e, op.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing admin app, got %v", e)
	}

	// Verify HTTP pagination (updated_at DESC, id DESC), state & owner filters, and detail endpoint.
	h := httpapi.Handler{Service: s, Authenticate: func(r *http.Request) (op.Principal, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer admin":
			return admin, nil
		case "Bearer dev":
			return dev, nil
		default:
			return op.Principal{}, op.ErrUnauthenticated
		}
	}}
	call := func(path, auth string, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/open-platform"+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != wantStatus {
			t.Fatalf("GET %s: got %d want %d: %s", path, w.Code, wantStatus, w.Body.String())
		}
		return w
	}

	call("/admin/apps", "", http.StatusUnauthorized)
	call("/admin/apps", "Bearer dev", http.StatusForbidden)
	call("/admin/apps/"+app1.ID, "Bearer dev", http.StatusForbidden)
	call("/admin/apps?state=invalid", "Bearer admin", http.StatusBadRequest)
	call("/admin/apps?after=bad-cursor", "Bearer admin", http.StatusBadRequest)
	call("/admin/apps?unknown=1", "Bearer admin", http.StatusBadRequest)

	var all []op.AdminApplication
	after := ""
	for {
		q := "/admin/apps?limit=2"
		if after != "" {
			q += "&after=" + after
		}
		w := call(q, "Bearer admin", http.StatusOK)
		var p op.Page[op.AdminApplication]
		if e = json.Unmarshal(w.Body.Bytes(), &p); e != nil {
			t.Fatal(e)
		}
		all = append(all, p.Items...)
		if p.Next == "" {
			break
		}
		after = p.Next
	}
	wantOrder := []string{app1.ID, app4.ID, app3.ID, app2.ID}
	if len(all) != 4 {
		t.Fatalf("expected 4 apps, got %d", len(all))
	}
	for i, wantID := range wantOrder {
		if all[i].ID != wantID {
			t.Fatalf("order[%d] = %s, want %s (all=%+v)", i, all[i].ID, wantID, all)
		}
	}

	// Filter by state and owner.
	var pendingPage op.Page[op.AdminApplication]
	if e = json.Unmarshal(call("/admin/apps?state=pending", "Bearer admin", http.StatusOK).Body.Bytes(), &pendingPage); e != nil || len(pendingPage.Items) != 1 || pendingPage.Items[0].ID != app4.ID || pendingPage.Items[0].Owner != devTwo.Owner {
		t.Fatalf("unexpected pending filter result: %+v err=%v", pendingPage, e)
	}
	var ownerPage op.Page[op.AdminApplication]
	if e = json.Unmarshal(call("/admin/apps?owner=developer", "Bearer admin", http.StatusOK).Body.Bytes(), &ownerPage); e != nil || len(ownerPage.Items) != 2 || ownerPage.Items[0].ID != app1.ID || ownerPage.Items[1].ID != app2.ID {
		t.Fatalf("unexpected owner filter result: %+v err=%v", ownerPage, e)
	}
	var httpDetail op.AdminApplication
	if e = json.Unmarshal(call("/admin/apps/"+app1.ID, "Bearer admin", http.StatusOK).Body.Bytes(), &httpDetail); e != nil || httpDetail.ID != app1.ID || httpDetail.ActiveGrants != 1 || httpDetail.Owner != dev.Owner {
		t.Fatalf("unexpected HTTP admin app detail: %+v err=%v", httpDetail, e)
	}

	// Expiry drops active_grants to 0 without waiting for background Work().
	x.clock.Add(601)
	expiredDetail, e := s.AdminApplication(ctx, admin, app1.ID)
	if e != nil || expiredDetail.ActiveGrants != 0 {
		t.Fatalf("expected active_grants=0 after grant expiry, got %+v err=%v", expiredDetail, e)
	}
}
