package openplatform_test

import (
	"context"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"testing"
	"time"
)

func TestBacklogObservesPendingNoticesAndRetentionLag(t *testing.T) {
	x := setup(t)
	s := x.s

	if _, e := (&op.Service{}).Backlog(ctx); !errors.Is(e, op.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable without repository, got %v", e)
	}

	app := approve(t, s, apply(t, s, dev, "backlog-app", []string{"profile"}, "public"), []string{"profile"}, 100)
	tok := tokenFor(t, s, alice, app, "backlog-live", []string{"profile"})
	if _, e := s.Read(ctx, tok.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal(e)
	}

	clean, e := s.Backlog(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if clean.HasBacklog || clean.OldestExpiredAt != nil || clean.MaxLagSeconds != 0 {
		t.Fatalf("expected zero backlog for live records, got %+v", clean)
	}

	// Non-expiry suspension creates pending notice backlog immediately even before grant expires_at.
	app2 := approve(t, s, apply(t, s, dev, "backlog-sus", []string{"profile"}, "public"), []string{"profile"}, 100)
	_ = tokenFor(t, s, bob, app2, "backlog-bob", []string{"profile"})
	if _, e = s.Review(ctx, admin, app2.ID, "sus-backlog", op.ReviewInput{Revision: app2.Revision, Decision: "suspend", ApprovedScopes: []string{}, Note: "suspend"}); e != nil {
		t.Fatal(e)
	}
	suspendedAt := s.Now()
	x.clock.Add(45)
	susBacklog, e := s.Backlog(ctx)
	if e != nil || !susBacklog.HasBacklog || !susBacklog.PendingNotices.HasBacklog || susBacklog.PendingNotices.OldestExpiredAt == nil || !susBacklog.PendingNotices.OldestExpiredAt.Equal(suspendedAt) || susBacklog.PendingNotices.LagSeconds != 45 || susBacklog.MaxLagSeconds != 45 {
		t.Fatalf("expected pending notice backlog for suspended app, got %+v err=%v", susBacklog, e)
	}
	if _, e = s.Work(ctx, 100); e != nil {
		t.Fatal(e)
	}
	afterWork, e := s.Backlog(ctx)
	if e != nil || afterWork.HasBacklog {
		t.Fatalf("expected backlog cleared after Work(), got %+v err=%v", afterWork, e)
	}

	// Advance clock 26 hours and seed overdue records across all categories.
	x.clock.Store(time.Date(2026, 11, 4, 2, 0, 0, 0, time.UTC).Unix())
	now := s.Now()
	for _, stmt := range []string{
		`INSERT INTO open_platform.requests(actor,key,digest,result,created_at) VALUES('old','k1','h','{}',$1::timestamptz - interval '26 hours')`,
		`INSERT INTO open_platform.events(actor,kind,object_id,operation,created_at) VALUES('old','ev','obj','op',$1::timestamptz - interval '1 year' - interval '3 hours')`,
		`INSERT INTO open_platform.notices(id,app_id,document,created_at) VALUES('old-notice',$2,'{"id":"old-notice"}',$1::timestamptz - interval '1 year' - interval '5 hours')`,
		`INSERT INTO open_platform.quotas(app_id,day,used) VALUES($2,'2026-11-01',1)`,
	} {
		var err error
		if stmt == `INSERT INTO open_platform.notices(id,app_id,document,created_at) VALUES('old-notice',$2,'{"id":"old-notice"}',$1::timestamptz - interval '1 year' - interval '5 hours')` {
			_, err = x.db.Exec(stmt, now, app.ID)
		} else if stmt == `INSERT INTO open_platform.quotas(app_id,day,used) VALUES($2,'2026-11-01',1)` {
			_, err = x.db.Exec(`INSERT INTO open_platform.quotas(app_id,day,used) VALUES($1,'2026-11-01',1) ON CONFLICT(app_id,day) DO NOTHING`, app2.ID)
		} else {
			_, err = x.db.Exec(stmt, now)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	b, e := s.Backlog(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if !b.HasBacklog || !b.PendingNotices.HasBacklog || !b.ExpiredRequests.HasBacklog || !b.ExpiredTokens.HasBacklog || !b.ExpiredConsents.HasBacklog || !b.ExpiredEvents.HasBacklog || !b.ExpiredNotices.HasBacklog || !b.ExpiredQuotas.HasBacklog {
		t.Fatalf("expected all 7 categories to report backlog: %+v", b)
	}
	// The setup wrote real receipts on November 1; the first became eligible on November 2.
	if b.ExpiredRequests.LagSeconds != int64(now.Sub(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))/time.Second) {
		t.Fatalf("unexpected request lag: %d", b.ExpiredRequests.LagSeconds)
	}
	if b.ExpiredEvents.LagSeconds != int64((3*time.Hour)/time.Second) {
		t.Fatalf("unexpected event lag: %d", b.ExpiredEvents.LagSeconds)
	}
	if b.ExpiredNotices.LagSeconds != int64((5*time.Hour)/time.Second) {
		t.Fatalf("unexpected notice lag: %d", b.ExpiredNotices.LagSeconds)
	}
	// 2026-11-01 quota became due at 2026-11-03T00:00:00Z -> 26h lag at 2026-11-04T02:00:00Z.
	if b.ExpiredQuotas.LagSeconds != int64((26*time.Hour)/time.Second) {
		t.Fatalf("unexpected quota lag: %d", b.ExpiredQuotas.LagSeconds)
	}
	// Earliest overdue item is alice's token/grant from 2026-11-01T00:10:00Z (73h50m lag).
	wantMaxLag := int64(now.Sub(time.Date(2026, 11, 1, 0, 10, 0, 0, time.UTC)) / time.Second)
	if b.MaxLagSeconds != wantMaxLag || b.OldestExpiredAt == nil || !b.OldestExpiredAt.Equal(time.Date(2026, 11, 1, 0, 10, 0, 0, time.UTC)) {
		t.Fatalf("unexpected global oldest/max lag: %+v wantMaxLag=%d", b, wantMaxLag)
	}

	// Drain Work and Cleanup, then verify backlog returns to clean state.
	if _, e = s.Work(ctx, 100); e != nil {
		t.Fatal(e)
	}
	for range 3 {
		if _, e = s.Cleanup(ctx, 100); e != nil {
			t.Fatal(e)
		}
	}
	drained, e := s.Backlog(ctx)
	if e != nil || drained.HasBacklog || drained.MaxLagSeconds != 0 || drained.OldestExpiredAt != nil {
		t.Fatalf("expected zero backlog after Work+Cleanup drain, got %+v err=%v", drained, e)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.Backlog(cancelled); !errors.Is(e, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", e)
	}
}

func TestBacklogUsesCleanupCalendarOnLeapDay(t *testing.T) {
	x := setup(t)
	x.clock.Store(time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC).Unix())
	app := apply(t, x.s, dev, "calendar", []string{"profile"}, "public")
	created := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	if _, err := x.db.Exec(`INSERT INTO open_platform.events(actor,kind,object_id,operation,created_at) VALUES('test','test','test','test',$1)`, created); err != nil {
		t.Fatal(err)
	}
	if _, err := x.db.Exec(`INSERT INTO open_platform.notices(id,app_id,created_at,document) VALUES('calendar',$1,$2,'{}')`, app.ID, created); err != nil {
		t.Fatal(err)
	}
	b, err := x.s.Backlog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []op.CategoryBacklog{b.ExpiredEvents, b.ExpiredNotices} {
		if !c.HasBacklog || c.LagSeconds != 43200 || c.OldestExpiredAt == nil || !c.OldestExpiredAt.Equal(x.s.Now().Add(-12*time.Hour)) {
			t.Fatalf("leap day backlog: %+v", c)
		}
	}
	if _, err = x.s.Cleanup(ctx, 100); err != nil {
		t.Fatal(err)
	}
	b, err = x.s.Backlog(ctx)
	if err != nil || b.ExpiredEvents.HasBacklog || b.ExpiredNotices.HasBacklog {
		t.Fatalf("after cleanup: %+v %v", b, err)
	}
}
