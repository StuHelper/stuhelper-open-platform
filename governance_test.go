package openplatform_test

import (
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

func TestQuotaHeadersPendingAckOverdueInspectionAndArchiveRetention(t *testing.T) {
	x := setup(t)
	s := x.s

	h := httpapi.Handler{Service: s, Authenticate: func(r *http.Request) (op.Principal, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer admin":
			return admin, nil
		case "Bearer dev":
			return dev, nil
		case "Bearer bob":
			return bob, nil
		default:
			return op.Principal{}, op.ErrUnauthenticated
		}
	}}
	call := func(method, path, auth, key, body string, wantStatus int) *httptest.ResponseRecorder {
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
		return w
	}

	// 1. X-RateLimit-Limit / X-RateLimit-Remaining and developer GET /apps/{id} quota_used.
	app1 := approve(t, s, apply(t, s, dev, "gov-app-1", []string{"profile", "student_status", "schools"}, "public"), []string{"profile", "student_status", "schools"}, 2)
	var detailBefore op.Application
	if err := json.Unmarshal(call(http.MethodGet, "/apps/"+app1.ID, "Bearer dev", "", "", http.StatusOK).Body.Bytes(), &detailBefore); err != nil || detailBefore.QuotaUsed == nil || *detailBefore.QuotaUsed != 0 {
		t.Fatalf("expected initial quota_used=0, got %+v err=%v", detailBefore, err)
	}

	tok := tokenFor(t, s, alice, app1, "gov-tok-1", []string{"profile", "student_status", "schools"})
	w1 := call(http.MethodGet, "/data/profile", "Bearer "+tok.AccessToken, "", "", http.StatusOK)
	if w1.Header().Get("X-RateLimit-Limit") != "2" || w1.Header().Get("X-RateLimit-Remaining") != "1" {
		t.Fatalf("unexpected rate headers on first read: %v", w1.Header())
	}
	w2 := call(http.MethodGet, "/data/profile", "Bearer "+tok.AccessToken, "", "", http.StatusOK)
	if w2.Header().Get("X-RateLimit-Limit") != "2" || w2.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("unexpected rate headers on second read: %v", w2.Header())
	}
	w3 := call(http.MethodGet, "/data/profile", "Bearer "+tok.AccessToken, "", "", http.StatusTooManyRequests)
	if w3.Header().Get("X-RateLimit-Limit") != "2" || w3.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("unexpected rate headers on 429 read: %v", w3.Header())
	}
	var detailAfter op.Application
	if err := json.Unmarshal(call(http.MethodGet, "/apps/"+app1.ID, "Bearer dev", "", "", http.StatusOK).Body.Bytes(), &detailAfter); err != nil || detailAfter.QuotaUsed == nil || *detailAfter.QuotaUsed != 2 {
		t.Fatalf("expected quota_used=2 after exhausting daily quota, got %+v err=%v", detailAfter, err)
	}

	// 2. pending_ack=true filtering and admin overdue notice inspection.
	gs, e := s.Grants(ctx, alice, "", 10)
	if e != nil || len(gs.Items) != 1 {
		t.Fatal(gs, e)
	}
	rev1, e := s.Revoke(ctx, alice, gs.Items[0].ID, "rev-s1", op.RevokeInput{Revision: gs.Items[0].Revision, Scopes: []string{"profile"}})
	if e != nil {
		t.Fatal(e)
	}
	x.clock.Add(5)
	rev2, e := s.Revoke(ctx, alice, rev1.ID, "rev-s2", op.RevokeInput{Revision: rev1.Revision, Scopes: []string{"student_status"}})
	if e != nil {
		t.Fatal(e)
	}
	x.clock.Add(5)
	if _, e = s.Revoke(ctx, alice, rev2.ID, "rev-s3", op.RevokeInput{Revision: rev2.Revision, Scopes: []string{"schools"}}); e != nil {
		t.Fatal(e)
	}

	// Create a second app with an older unacknowledged notice to verify ordering and pagination on /admin/notices/overdue.
	app2 := approve(t, s, apply(t, s, dev, "gov-app-2", []string{"profile"}, "public"), []string{"profile"}, 10)
	x.clock.Add(-60)
	_ = tokenFor(t, s, bob, app2, "gov-bob", []string{"profile"})
	bobGs, e := s.Grants(ctx, bob, "", 10)
	if e != nil || len(bobGs.Items) != 1 {
		t.Fatal(bobGs, e)
	}
	if _, e = s.Revoke(ctx, bob, bobGs.Items[0].ID, "rev-bob", op.RevokeInput{Revision: bobGs.Items[0].Revision, Scopes: []string{"profile"}}); e != nil {
		t.Fatal(e)
	}
	x.clock.Add(60)

	allNotices, e := s.Notices(ctx, dev, app1.ID, "", "", 10)
	if e != nil || len(allNotices.Items) != 3 {
		t.Fatalf("expected 3 notices on app1, got %+v err=%v", allNotices, e)
	}
	if _, e = s.Acknowledge(ctx, dev, app1.ID, "", allNotices.Items[0].ID, "ack-1", op.Acknowledgement{Status: "deleted", Note: ""}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Acknowledge(ctx, dev, app1.ID, "", allNotices.Items[1].ID, "ack-2", op.Acknowledgement{Status: "received", Note: ""}); e != nil {
		t.Fatal(e)
	}

	var pendingPage op.Page[op.Notice]
	if e = json.Unmarshal(call(http.MethodGet, "/apps/"+app1.ID+"/notices?pending_ack=true", "Bearer dev", "", "", http.StatusOK).Body.Bytes(), &pendingPage); e != nil || len(pendingPage.Items) != 2 {
		t.Fatalf("expected 2 pending_ack notices (received + unacknowledged), got %+v err=%v", pendingPage, e)
	}
	if pendingPage.Items[0].ID != allNotices.Items[1].ID || pendingPage.Items[1].ID != allNotices.Items[2].ID {
		t.Fatalf("unexpected pending_ack notice IDs: %+v", pendingPage.Items)
	}
	call(http.MethodGet, "/apps/"+app1.ID+"/notices?pending_ack=invalid", "Bearer dev", "", "", http.StatusBadRequest)

	// Advance 8 days so unacknowledged notices become overdue (> 7 days).
	x.clock.Add(int64(8 * 24 * time.Hour / time.Second))
	call(http.MethodGet, "/admin/notices/overdue", "", "", "", http.StatusUnauthorized)
	call(http.MethodGet, "/admin/notices/overdue", "Bearer dev", "", "", http.StatusForbidden)
	call(http.MethodGet, "/admin/notices/overdue?older_than_days=0", "Bearer admin", "", "", http.StatusBadRequest)

	var overdue1 op.Page[op.OverdueNoticeApplication]
	if e = json.Unmarshal(call(http.MethodGet, "/admin/notices/overdue?older_than_days=7&limit=1", "Bearer admin", "", "", http.StatusOK).Body.Bytes(), &overdue1); e != nil || len(overdue1.Items) != 1 || overdue1.Items[0].AppID != app2.ID || overdue1.Items[0].OverdueNotices != 1 || overdue1.Next == "" {
		t.Fatalf("unexpected overdue page 1: %+v err=%v", overdue1, e)
	}
	var overdue2 op.Page[op.OverdueNoticeApplication]
	if e = json.Unmarshal(call(http.MethodGet, "/admin/notices/overdue?older_than_days=7&limit=10&after="+overdue1.Next, "Bearer admin", "", "", http.StatusOK).Body.Bytes(), &overdue2); e != nil || len(overdue2.Items) != 1 || overdue2.Items[0].AppID != app1.ID || overdue2.Items[0].OverdueNotices != 2 {
		t.Fatalf("unexpected overdue page 2: %+v err=%v", overdue2, e)
	}

	// Completing statutory retention/deletion acks removes app1 from overdue list.
	if _, e = s.Acknowledge(ctx, dev, app1.ID, "", allNotices.Items[1].ID, "ack-2-final", op.Acknowledgement{Status: "retention_exception", Note: "Statutory audit obligation"}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Acknowledge(ctx, dev, app1.ID, "", allNotices.Items[2].ID, "ack-3-final", op.Acknowledgement{Status: "deleted", Note: ""}); e != nil {
		t.Fatal(e)
	}
	var overdueAfterAck op.Page[op.OverdueNoticeApplication]
	if e = json.Unmarshal(call(http.MethodGet, "/admin/notices/overdue?older_than_days=7", "Bearer admin", "", "", http.StatusOK).Body.Bytes(), &overdueAfterAck); e != nil || len(overdueAfterAck.Items) != 1 || overdueAfterAck.Items[0].AppID != app2.ID {
		t.Fatalf("expected app1 cleared from overdue inspection after completion acks: %+v err=%v", overdueAfterAck, e)
	}

	// 3. Developer archive stops active grants immediately, blocks resubmit/review, and releases 100-app quota after 12 months.
	archDev := op.Principal{Owner: "archive-developer"}
	firstApp := approve(t, s, apply(t, s, archDev, "arch-0", []string{"profile"}, "public"), []string{"profile"}, 100)
	liveTok := tokenFor(t, s, alice, firstApp, "arch-tok", []string{"profile"})
	for i := 1; i < 100; i++ {
		if _, e = s.Apply(ctx, archDev, "", fmt.Sprintf("arch-%d", i), op.ApplicationInput{Name: "Test", Purpose: "test", RedirectURIs: []string{"https://client.example/cb"}, RequestedScopes: []string{"profile"}, ClientType: "public"}); e != nil {
			t.Fatal(i, e)
		}
	}
	if _, e = s.Apply(ctx, archDev, "", "arch-overflow", op.ApplicationInput{Name: "Overflow", Purpose: "test", RedirectURIs: []string{"https://client.example/cb"}, RequestedScopes: []string{"profile"}, ClientType: "public"}); !errors.Is(e, op.ErrConflict) {
		t.Fatalf("expected 100-app quota conflict, got %v", e)
	}

	if _, e = s.Archive(ctx, bob, firstApp.ID, "wrong-owner", firstApp.Revision); !errors.Is(e, op.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for foreign owner archive, got %v", e)
	}
	archived, e := s.Archive(ctx, archDev, firstApp.ID, "do-archive", firstApp.Revision)
	if e != nil || archived.State != "suspended" || archived.ArchivedAt == nil {
		t.Fatalf("unexpected archive result: %+v err=%v", archived, e)
	}
	replayedArchive, e := s.Archive(ctx, archDev, firstApp.ID, "do-archive", firstApp.Revision)
	if e != nil || replayedArchive.ArchivedAt == nil || replayedArchive.Revision != archived.Revision {
		t.Fatalf("unexpected archive replay: %+v err=%v", replayedArchive, e)
	}
	if _, e = s.Archive(ctx, archDev, firstApp.ID, "archive-again", archived.Revision); !errors.Is(e, op.ErrConflict) {
		t.Fatalf("expected conflict archiving already archived app, got %v", e)
	}
	if _, e = s.Read(ctx, liveTok.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatalf("expected archived app token to stop immediately, got %v", e)
	}
	if _, e = s.Apply(ctx, archDev, firstApp.ID, "resubmit-archived", op.ApplicationInput{Name: "Resubmit", Purpose: "test", RedirectURIs: []string{"https://client.example/cb"}, RequestedScopes: []string{"profile"}, ClientType: "public", Revision: archived.Revision}); !errors.Is(e, op.ErrConflict) {
		t.Fatalf("expected resubmit of archived app to fail with ErrConflict, got %v", e)
	}
	if _, e = s.Review(ctx, admin, firstApp.ID, "approve-archived", op.ReviewInput{Revision: archived.Revision, Decision: "approve", ApprovedScopes: []string{"profile"}, Policy: firstApp.Policy, Note: "no"}); !errors.Is(e, op.ErrConflict) {
		t.Fatalf("expected review of archived app to fail with ErrConflict, got %v", e)
	}

	// Materialize withdrawal notice while archived; notice remains readable before 12 months.
	if _, e = s.Work(ctx, 100); e != nil {
		t.Fatal(e)
	}
	archNotices, e := s.ListNotices(ctx, archDev, firstApp.ID, "", true, "", 10)
	if e != nil || len(archNotices.Items) != 1 {
		t.Fatalf("expected archived app withdrawal notice to remain accessible, got %+v err=%v", archNotices, e)
	}

	// Before 12 months pass, Cleanup retains the archived app.
	x.clock.Add(int64(30 * 24 * time.Hour / time.Second))
	if _, e = s.Cleanup(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Application(ctx, archDev, firstApp.ID); e != nil {
		t.Fatalf("archived app deleted before 12-month retention expired: %v", e)
	}

	// Advance past 12 months from archival and notice creation; Cleanup removes archived app and releases quota.
	x.clock.Add(int64(370 * 24 * time.Hour / time.Second))
	for range 3 {
		if _, e = s.Cleanup(ctx, 100); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.Application(ctx, archDev, firstApp.ID); !errors.Is(e, op.ErrNotFound) {
		t.Fatalf("expected archived app removed after 12 months, got %v", e)
	}
	createdAfterRelease, e := s.Apply(ctx, archDev, "", "arch-released", op.ApplicationInput{Name: "New after release", Purpose: "test", RedirectURIs: []string{"https://client.example/cb"}, RequestedScopes: []string{"profile"}, ClientType: "public"})
	if e != nil || createdAfterRelease.ID == "" {
		t.Fatalf("expected developer quota released after archived app retention cleanup, got %+v err=%v", createdAfterRelease, e)
	}
}
