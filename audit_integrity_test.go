package openplatform_test

import (
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/auditquery"
	"testing"
	"time"
)

func TestEmptyCleanupPreservesAuditSnapshotAndMutationsRecordTargetsReasonsAndControlledClock(t *testing.T) {
	x := setup(t)
	s := x.s

	created := apply(t, s, dev, "audit-create", []string{"profile"}, "confidential")
	approved, e := s.Review(ctx, admin, created.ID, "audit-review", op.ReviewInput{
		Revision:       created.Revision,
		Decision:       "approve",
		ApprovedScopes: []string{"profile"},
		Policy:         op.Policy{GrantSeconds: 600, TokenSeconds: 300, DailyQuota: 50},
		Note:           "Approved with explicit audit reason",
	})
	if e != nil {
		t.Fatal(e)
	}
	cr, e := s.RotateCredential(ctx, dev, approved.ID, "audit-cred", 0)
	if e != nil {
		t.Fatal(e)
	}
	_, code, verifier := consent(t, s, alice, approved, "audit-consent", []string{"profile"})
	tok := exchange(t, s, approved, code, verifier, cr.Secret)

	// Replay the already-consumed authorization code with valid credentials and PKCE.
	if _, e = s.Exchange(ctx, op.TokenInput{
		GrantType:    "authorization_code",
		ClientID:     approved.ID,
		RedirectURI:  approved.RedirectURIs[0],
		Code:         code,
		Verifier:     verifier,
		ClientSecret: cr.Secret,
	}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal("expected replay rejection, got", e)
	}
	if _, e = s.Read(ctx, tok.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal("replayed token remained usable", e)
	}

	// Issue a fresh grant, revoke it, and acknowledge via both developer session and app Basic secret.
	_, code2, verifier2 := consent(t, s, alice, approved, "audit-consent-2", []string{"profile"})
	_ = exchange(t, s, approved, code2, verifier2, cr.Secret)
	grants, e := s.Grants(ctx, alice, "", 10)
	if e != nil || len(grants.Items) != 1 {
		t.Fatal(grants, e)
	}
	grantID := grants.Items[0].ID
	if _, e = s.Revoke(ctx, alice, grantID, "audit-revoke", op.RevokeInput{Revision: grants.Items[0].Revision, Scopes: []string{"profile"}}); e != nil {
		t.Fatal(e)
	}
	notices, e := s.Notices(ctx, dev, approved.ID, "", "", 10)
	if e != nil || len(notices.Items) != 1 {
		t.Fatal(notices, e)
	}
	noticeID := notices.Items[0].ID
	if _, e = s.Acknowledge(ctx, dev, approved.ID, "", noticeID, "audit-ack-dev", op.Acknowledgement{Status: "retention_exception", Note: "Statutory tax retention"}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Acknowledge(ctx, op.Principal{}, approved.ID, cr.Secret, noticeID, "audit-ack-app", op.Acknowledgement{Status: "deleted", Note: "Purged after retention window"}); e != nil {
		t.Fatal(e)
	}

	scopes := []auditquery.Scope{{School: "*", Group: "*", Module: "open-platform"}}
	until := s.Now().Add(time.Minute)

	// A-02: Verify audit lookup by target object ID, action name, actor, and reason.
	submitted, e := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Target: created.ID, Action: "application_submitted", Until: until, Limit: 10})
	if e != nil || len(submitted.Records) != 1 || submitted.Records[0].Actor != dev.Owner {
		t.Fatalf("expected application_submitted for %s, got %+v err=%v", created.ID, submitted.Records, e)
	}
	reviewed, e := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Target: created.ID, Action: "application_reviewed", Until: until, Limit: 10})
	if e != nil || len(reviewed.Records) != 1 || reviewed.Records[0].Actor != admin.Owner || reviewed.Records[0].Reason != "Approved with explicit audit reason" {
		t.Fatalf("expected application_reviewed with reason, got %+v err=%v", reviewed.Records, e)
	}
	replayedAudit, e := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Target: grantID, Action: "code_replay_revoked", Until: until, Limit: 10})
	if e != nil || len(replayedAudit.Records) != 1 || replayedAudit.Records[0].Actor != "app:"+approved.ID {
		t.Fatalf("expected code_replay_revoked audit record, got %+v err=%v", replayedAudit.Records, e)
	}
	acks, e := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Target: noticeID, Action: "notice_acknowledged", Until: until, Limit: 10})
	if e != nil || len(acks.Records) != 2 {
		t.Fatalf("expected 2 notice_acknowledged records, got %+v err=%v", acks.Records, e)
	}
	seenDev, seenApp := false, false
	for _, rec := range acks.Records {
		if rec.Actor == dev.Owner && rec.Reason == "Statutory tax retention" {
			seenDev = true
		}
		if rec.Actor == "app:"+approved.ID && rec.Reason == "Purged after retention window" {
			seenApp = true
		}
	}
	if !seenDev || !seenApp {
		t.Fatalf("unexpected ack actors/reasons: %+v", acks.Records)
	}

	// A-01: Open page 1 of public audit, run Cleanup that deletes 0 audit rows, then read page 2 with Snapshot.
	page1, e := x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Until: until, Limit: 2})
	if e != nil || len(page1.Records) != 2 || page1.Snapshot == "" {
		t.Fatalf("page1 failed: %+v err=%v", page1, e)
	}
	if _, e = s.Cleanup(ctx, 100); e != nil {
		t.Fatal(e)
	}
	last := page1.Records[len(page1.Records)-1]
	page2, e := x.repo.ReadAudit(ctx, auditquery.Request{
		Scopes:   scopes,
		Until:    until,
		Snapshot: page1.Snapshot,
		Before:   &auditquery.Position{Time: last.CreatedAt, Source: last.Source, ID: last.ID},
		Limit:    10,
	})
	if e != nil || len(page2.Records) == 0 {
		t.Fatalf("0-row Cleanup invalidated active audit snapshot: page2=%+v err=%v", page2, e)
	}

	// A-13.1: Advancing the controlled service clock (without wall-clock sleep or raw SQL backdating)
	// expires 24-hour idempotency replays and 12-month audit events, and real event deletion invalidates Snapshot.
	x.clock.Add(int64((25 * time.Hour) / time.Second))
	if _, e = s.Cleanup(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.requests`); n != 0 {
		t.Fatalf("expected requests written via controlled clock to expire after 25h, remaining=%d", n)
	}
	// Still < 12 months, so audit events were not deleted and Snapshot remains valid.
	if _, e = x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Until: until, Snapshot: page1.Snapshot, Limit: 1}); e != nil {
		t.Fatalf("snapshot invalidated before 12-month event retention elapsed: %v", e)
	}

	x.clock.Add(int64((370 * 24 * time.Hour) / time.Second))
	if _, e = s.Cleanup(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.events`); n != 0 {
		t.Fatalf("expected events written via controlled clock to expire after >12m, remaining=%d", n)
	}
	if _, e = x.repo.ReadAudit(ctx, auditquery.Request{Scopes: scopes, Until: until, Snapshot: page1.Snapshot, Limit: 1}); !errors.Is(e, auditquery.ErrUnavailable) {
		t.Fatalf("expected real event deletion to invalidate snapshot, got %v", e)
	}
}
