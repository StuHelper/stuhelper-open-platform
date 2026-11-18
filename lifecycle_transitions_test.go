package openplatform_test

import (
	"database/sql"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"testing"
	"time"
)

func TestRevokeAndReconsentStateMachineSuspendedResubmitAckMonotonicityAndTerminationTimestamps(t *testing.T) {
	x := setup(t)
	s := x.s

	// 1. A-04(1): Expired grant before Work() runs must NOT return fake active state on partial Revoke,
	// and must emit termination notice for ALL original scopes.
	app := approve(t, s, apply(t, s, dev, "lifecycle-app", []string{"profile", "schedule"}, "confidential"), []string{"profile", "schedule"}, 100)
	cr, err := s.RotateCredential(ctx, dev, app.ID, "lifecycle-secret", 0)
	if err != nil || cr.Secret == "" {
		t.Fatal(cr, err)
	}
	c1, code1, v1 := consent(t, s, alice, app, "grant-expire", []string{"profile", "schedule"})
	_ = c1
	_ = exchange(t, s, app, code1, v1, cr.Secret)

	gs, err := s.Grants(ctx, alice, "", 10)
	if err != nil || len(gs.Items) != 1 {
		t.Fatal(gs, err)
	}
	initialGrant := gs.Items[0]

	// Advance clock past GrantSeconds (600s) without running Work().
	x.clock.Add(605)
	revoked, err := s.Revoke(ctx, alice, initialGrant.ID, "revoke-expired-partial", op.RevokeInput{
		Revision: initialGrant.Revision,
		Scopes:   []string{"profile"},
	})
	if err != nil {
		t.Fatalf("expected expired grant convergence on Revoke, got err=%v", err)
	}
	if revoked.State != "revoked" || len(revoked.Scopes) != 0 {
		t.Fatalf("expired grant returned active or retained scopes on partial Revoke: %+v", revoked)
	}
	notices, err := s.Notices(ctx, dev, app.ID, "", "", 10)
	if err != nil || len(notices.Items) != 1 || notices.Items[0].Reason != "expired" || len(notices.Items[0].Scopes) != 2 {
		t.Fatalf("expected single expired notice covering both scopes, got %+v err=%v", notices.Items, err)
	}

	// 2. A-04(2): Calling Revoke again on an already-revoked grant must fail with ErrConflict and emit no duplicate notice.
	if _, err = s.Revoke(ctx, alice, revoked.ID, "revoke-again", op.RevokeInput{
		Revision: revoked.Revision,
		Scopes:   []string{"profile"},
	}); !errors.Is(err, op.ErrConflict) {
		t.Fatalf("expected ErrConflict revoking already-revoked grant, got %v", err)
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.notices WHERE app_id=$1`, app.ID); n != 1 {
		t.Fatalf("duplicate notice created: count=%d", n)
	}

	// 3. A-04(3): Re-consenting after grant expiry (before Work() runs) must NOT emit a deletion notice
	// for scopes that the user continuously re-authorizes, only for dropped scopes.
	_, code2, v2 := consent(t, s, bob, app, "bob-initial", []string{"profile", "schedule"})
	_ = exchange(t, s, app, code2, v2, cr.Secret)
	x.clock.Add(605) // bob's grant is now expired, Work() has not run
	_, code3, v3 := consent(t, s, bob, app, "bob-reconsent-profile", []string{"profile"})
	bobTok := exchange(t, s, app, code3, v3, cr.Secret)
	if _, err = s.Read(ctx, bobTok.AccessToken, "profile", op.Query{}); err != nil {
		t.Fatal(err)
	}
	allNotices, err := s.Notices(ctx, dev, app.ID, "", "", 10)
	if err != nil || len(allNotices.Items) != 2 {
		t.Fatalf("expected 2 notices total, got %+v err=%v", allNotices.Items, err)
	}
	bobNotice := allNotices.Items[1]
	if bobNotice.Reason != "expired" || len(bobNotice.Scopes) != 1 || bobNotice.Scopes[0] != "schedule" {
		t.Fatalf("re-authorized scope profile was wrongly included in deletion notice: %+v", bobNotice)
	}

	// 4. A-09(2): Notice acknowledgement must be monotonic: retention_exception -> received must fail with ErrConflict
	// and preserve the statutory retention note; retention_exception -> deleted must succeed.
	ack1, err := s.Acknowledge(ctx, dev, app.ID, "", bobNotice.ID, "ack-retention", op.Acknowledgement{
		Status: "retention_exception",
		Note:   "Statutory dispute preservation",
	})
	if err != nil || ack1.Acknowledgement != "retention_exception" {
		t.Fatal(ack1, err)
	}
	if _, err = s.Acknowledge(ctx, dev, app.ID, "", bobNotice.ID, "ack-regress-received", op.Acknowledgement{
		Status: "received",
		Note:   "",
	}); !errors.Is(err, op.ErrConflict) {
		t.Fatalf("expected ErrConflict regressing retention_exception -> received, got %v", err)
	}
	checkPages, err := s.Notices(ctx, dev, app.ID, "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if checkPages.Items[1].Acknowledgement != "retention_exception" || checkPages.Items[1].Note != "Statutory dispute preservation" {
		t.Fatalf("statutory retention note was overwritten: %+v", checkPages.Items[1])
	}
	ack2, err := s.Acknowledge(ctx, dev, app.ID, "", bobNotice.ID, "ack-deleted", op.Acknowledgement{
		Status: "deleted",
		Note:   "Dispute resolved and deleted",
	})
	if err != nil || ack2.Acknowledgement != "deleted" {
		t.Fatal(ack2, err)
	}

	// 5. A-09(1): Resubmission from changes_requested preserves reviewer note and clears secret_hash if switched to public;
	// suspended application CANNOT be self-resubmitted by developer to wipe suspension note.
	app2 := apply(t, s, dev, "resubmit-app", []string{"profile"}, "confidential")
	if _, err = s.RotateCredential(ctx, dev, app2.ID, "app2-secret", 0); err != nil {
		t.Fatal(err)
	}
	changesReq, err := s.Review(ctx, admin, app2.ID, "req-changes", op.ReviewInput{
		Revision:       app2.Revision,
		Decision:       "changes_requested",
		ApprovedScopes: []string{},
		Note:           "Clarify data retention details",
	})
	if err != nil {
		t.Fatal(err)
	}
	resubmitted, err := s.Apply(ctx, dev, app2.ID, "resubmit-public", op.ApplicationInput{
		Name:            "Updated Public App",
		Purpose:         "Clarified purpose",
		RedirectURIs:    []string{"https://client.example/callback"},
		RequestedScopes: []string{"profile"},
		ClientType:      "public",
		Revision:        changesReq.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resubmitted.Note != "Clarify data retention details" {
		t.Fatalf("expected previous review note to be preserved on resubmit, got %q", resubmitted.Note)
	}
	var secretHash string
	if err = x.db.QueryRow(`SELECT secret_hash FROM open_platform.apps WHERE id=$1`, app2.ID).Scan(&secretHash); err != nil || secretHash != "" {
		t.Fatalf("expected secret_hash cleared when switching to public, got %q err=%v", secretHash, err)
	}

	suspendTime := s.Now().Add(10 * time.Second)
	x.clock.Store(suspendTime.Unix())
	suspended, err := s.Review(ctx, admin, app2.ID, "suspend-violation", op.ReviewInput{
		Revision:       resubmitted.Revision,
		Decision:       "suspend",
		ApprovedScopes: []string{},
		Note:           "Policy violation: unauthorized scraping",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Apply(ctx, dev, app2.ID, "illegal-self-unsuspend", op.ApplicationInput{
		Name:            "Clean Name",
		Purpose:         "Clean Purpose",
		RedirectURIs:    []string{"https://client.example/callback"},
		RequestedScopes: []string{"profile"},
		ClientType:      "public",
		Revision:        suspended.Revision,
	}); !errors.Is(err, op.ErrConflict) {
		t.Fatalf("expected ErrConflict when developer resubmits suspended app, got %v", err)
	}
	afterAttempt, err := s.Application(ctx, admin, app2.ID)
	if err != nil || afterAttempt.State != "suspended" || afterAttempt.Note != "Policy violation: unauthorized scraping" {
		t.Fatalf("suspended app state or note altered: %+v err=%v", afterAttempt, err)
	}

	// 6. A-13(2): Verify updated_at and terminated_at timestamps are recorded using controlled clock on apps and grants,
	// and cleared when re-activated.
	var appUpdated time.Time
	var appTerminated sql.NullTime
	if err = x.db.QueryRow(`SELECT updated_at, terminated_at FROM open_platform.apps WHERE id=$1`, app2.ID).Scan(&appUpdated, &appTerminated); err != nil {
		t.Fatal(err)
	}
	if !appUpdated.Equal(suspendTime) || !appTerminated.Valid || !appTerminated.Time.Equal(suspendTime) {
		t.Fatalf("unexpected app timestamps: updated=%v terminated=%+v want=%v", appUpdated, appTerminated, suspendTime)
	}
	reapproveTime := suspendTime.Add(30 * time.Second)
	x.clock.Store(reapproveTime.Unix())
	reapproved := approve(t, s, suspended, []string{"profile"}, 50)
	_ = reapproved
	if err = x.db.QueryRow(`SELECT updated_at, terminated_at FROM open_platform.apps WHERE id=$1`, app2.ID).Scan(&appUpdated, &appTerminated); err != nil {
		t.Fatal(err)
	}
	if !appUpdated.Equal(reapproveTime) || appTerminated.Valid {
		t.Fatalf("expected terminated_at cleared on re-approval: updated=%v terminated=%+v", appUpdated, appTerminated)
	}

	var grantUpdated time.Time
	var grantTerminated sql.NullTime
	if err = x.db.QueryRow(`SELECT updated_at, terminated_at FROM open_platform.grants WHERE id=$1`, initialGrant.ID).Scan(&grantUpdated, &grantTerminated); err != nil {
		t.Fatal(err)
	}
	if !grantTerminated.Valid || grantUpdated.IsZero() {
		t.Fatalf("expected revoked grant to record terminated_at, got updated=%v terminated=%+v", grantUpdated, grantTerminated)
	}
}
