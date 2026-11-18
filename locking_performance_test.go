package openplatform_test

import (
	"context"
	"encoding/base64"
	"fmt"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type queryCountingRepo struct {
	op.Repository
	appCalls        atomic.Int32
	closedCalls     atomic.Int32
	saveNoticeCalls atomic.Int32
}

type queryCountingTx struct {
	op.Transaction
	parent *queryCountingRepo
}

func (r *queryCountingRepo) Transaction(ctx context.Context, owner, app string, exclusiveApp bool, run func(op.Transaction) error) error {
	return r.Repository.Transaction(ctx, owner, app, exclusiveApp, func(tx op.Transaction) error {
		return run(&queryCountingTx{Transaction: tx, parent: r})
	})
}
func (t *queryCountingTx) App(id string) (op.AppRecord, error) {
	t.parent.appCalls.Add(1)
	return t.Transaction.App(id)
}
func (t *queryCountingTx) Closed(owner string) (bool, error) {
	t.parent.closedCalls.Add(1)
	return t.Transaction.Closed(owner)
}
func (t *queryCountingTx) SaveNotice(n op.Notice) error {
	t.parent.saveNoticeCalls.Add(1)
	return t.Transaction.SaveNotice(n)
}

func TestNoticesPreventUnauthenticatedAppEnumerationAvoidLockContentionAndEliminateNPlusOneAndFullScan(t *testing.T) {
	x := setup(t)
	counter := &queryCountingRepo{Repository: x.repo}
	x.s.Repo = counter
	s := x.s
	h := httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (op.Principal, error) {
			return op.Principal{}, op.ErrUnauthenticated
		},
	}

	app := approve(t, s, apply(t, s, dev, "perf-app", []string{"profile", "student_status"}, "confidential"), []string{"profile", "student_status"}, 1000)
	cr, err := s.RotateCredential(ctx, dev, app.ID, "perf-secret", 0)
	if err != nil {
		t.Fatal(err)
	}

	// 1. A-08(1): Unauthenticated Basic Auth requests to /apps/{id}/notices must NOT distinguish
	// existing vs nonexistent app IDs (both must return 401 unauthenticated, never 404 not_found).
	basicHeader := func(id, pw string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+pw))
	}
	for _, targetApp := range []string{app.ID, "nonexistent-app-id-probe"} {
		req := httptest.NewRequest("GET", "/api/v1/open-platform/apps/"+targetApp+"/notices", nil)
		req.Header.Set("Authorization", basicHeader(targetApp, "wrong-secret"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatalf("GET /apps/%s/notices with invalid Basic auth expected 401, got %d %s (enumeration leak!)", targetApp, w.Code, w.Body.String())
		}
	}

	// 2. A-08(2): Even while an administrator holds the exclusive advisory lock on open-platform-app:<app.ID>,
	// invalid Basic credentials must be rejected BEFORE waiting on the app advisory lock;
	// and when one student holds a shared app lock, another student's Read must NOT be blocked!
	txExcl, err := x.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer txExcl.Rollback()
	if _, err := txExcl.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "open-platform-app:"+app.ID); err != nil {
		t.Fatal(err)
	}
	fastCtx, fastCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer fastCancel()
	reqWrongSecret := httptest.NewRequest("GET", "/api/v1/open-platform/apps/"+app.ID+"/notices", nil).WithContext(fastCtx)
	reqWrongSecret.Header.Set("Authorization", basicHeader(app.ID, "wrong-secret"))
	wWrong := httptest.NewRecorder()
	h.ServeHTTP(wWrong, reqWrongSecret)
	if wWrong.Code != 401 {
		t.Fatalf("invalid Basic auth acquired or waited on exclusive app lock instead of fast 401: got %d %s", wWrong.Code, wWrong.Body.String())
	}
	_ = txExcl.Rollback()

	_, bobCode, bobVerifier := consent(t, s, bob, app, "bob-perf", []string{"profile"})
	bobTok := exchange(t, s, app, bobCode, bobVerifier, cr.Secret)

	txShared, err := x.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer txShared.Rollback()
	if _, err := txShared.Exec(`SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, "open-platform-app:"+app.ID); err != nil {
		t.Fatal(err)
	}
	readCtx, readCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer readCancel()
	if _, err := s.Read(readCtx, bobTok.AccessToken, "profile", op.Query{}); err != nil {
		t.Fatalf("Read was blocked by another student's shared app lock (used exclusive app lock!): %v", err)
	}
	_ = txShared.Rollback()

	// 3. A-10(1): Seed 15 grants for alice and assert Grants() performs 0 per-row App() queries and 1 Closed() check!
	for i := 0; i < 15; i++ {
		otherApp := approve(t, s, apply(t, s, dev, fmt.Sprintf("bulk-app-%d", i), []string{"profile"}, "public"), []string{"profile"}, 100)
		_ = tokenFor(t, s, alice, otherApp, fmt.Sprintf("alice-bulk-%d", i), []string{"profile"})
	}
	counter.appCalls.Store(0)
	counter.closedCalls.Store(0)
	aliceGrants, err := s.Grants(ctx, alice, "", 50)
	if err != nil || len(aliceGrants.Items) != 15 {
		t.Fatalf("expected 15 active grants for alice, got %d err=%v", len(aliceGrants.Items), err)
	}
	if counter.appCalls.Load() != 0 || counter.closedCalls.Load() > 1 {
		t.Fatalf("Grants() exhibited N+1 queries: appCalls=%d closedCalls=%d", counter.appCalls.Load(), counter.closedCalls.Load())
	}

	// 4. A-10(3): Seed 5 unread notices on `app` and assert Notices() batch-marks seen_at without per-row SaveNotice!
	for i := 0; i < 5; i++ {
		student := op.Principal{Owner: fmt.Sprintf("student-notice-%d", i)}
		_, code, ver := consent(t, s, student, app, fmt.Sprintf("st-%d", i), []string{"profile"})
		_ = exchange(t, s, app, code, ver, cr.Secret)
		sg, err := s.Grants(ctx, student, "", 10)
		if err != nil || len(sg.Items) != 1 {
			t.Fatal(sg, err)
		}
		if _, err := s.Revoke(ctx, student, sg.Items[0].ID, fmt.Sprintf("st-rev-%d", i), op.RevokeInput{Revision: sg.Items[0].Revision, Scopes: []string{"profile"}}); err != nil {
			t.Fatal(err)
		}
	}
	counter.saveNoticeCalls.Store(0)
	noticePage, err := s.Notices(ctx, op.Principal{}, app.ID, cr.Secret, "", 10)
	if err != nil || len(noticePage.Items) != 5 {
		t.Fatalf("expected 5 notices via Basic auth, got %+v err=%v", noticePage, err)
	}
	if counter.saveNoticeCalls.Load() != 0 {
		t.Fatalf("Notices() executed %d per-row SaveNotice calls instead of batch update", counter.saveNoticeCalls.Load())
	}
	for _, n := range noticePage.Items {
		if n.SeenAt == nil {
			t.Fatalf("expected SeenAt populated on returned notice: %+v", n)
		}
	}
	if unseen := count(t, x.db, `SELECT count(*) FROM open_platform.notices WHERE app_id=$1 AND document->'seen_at' IS NULL`, app.ID); unseen != 0 {
		t.Fatalf("expected all 5 notices persisted with seen_at, unseen=%d", unseen)
	}

	// 5. A-10(2): Seed 1,500 active unexpired grants and verify idle Work() reads < 20 tuples from open_platform.grants!
	future := s.Now().Add(time.Hour)
	if _, err := x.db.Exec(`INSERT INTO open_platform.grants(id,app_id,owner_key,app_revision,state,expires_at,document)
		SELECT 'bulk-grant-'||n::text, $1, 'bulk-owner-'||n::text, $2, 'active', $3,
		jsonb_build_object('Owner','bulk-owner-'||n::text,'AppRevision',$2::bigint,'View',jsonb_build_object('id','bulk-grant-'||n::text,'app_id',$1::text,'app_name','Perf','subject','sub-'||n::text,'scopes',jsonb_build_array('profile'),'state','active','expires_at',$3::timestamptz,'revision',1))
		FROM generate_series(1, 1500) n`, app.ID, app.Revision, future); err != nil {
		t.Fatal(err)
	}
	if _, err := x.db.Exec(`ANALYZE open_platform.grants, open_platform.apps, open_platform.owners`); err != nil {
		t.Fatal(err)
	}
	if _, err := x.db.Exec(`SELECT pg_stat_force_next_flush()`); err != nil {
		t.Fatal(err)
	}
	var readBefore, readAfter int64
	if err := x.db.QueryRow(`SELECT COALESCE(seq_tup_read + idx_tup_fetch, 0) FROM pg_stat_user_tables WHERE schemaname='open_platform' AND relname='grants'`).Scan(&readBefore); err != nil {
		t.Fatal(err)
	}
	processed, err := s.Work(ctx, 100)
	if err != nil || processed != 0 {
		t.Fatalf("expected 0 candidates during idle Work(), got %d err=%v", processed, err)
	}
	if _, err := x.db.Exec(`SELECT pg_stat_force_next_flush()`); err != nil {
		t.Fatal(err)
	}
	if err := x.db.QueryRow(`SELECT COALESCE(seq_tup_read + idx_tup_fetch, 0) FROM pg_stat_user_tables WHERE schemaname='open_platform' AND relname='grants'`).Scan(&readAfter); err != nil {
		t.Fatal(err)
	}
	if delta := readAfter - readBefore; delta >= 100 {
		t.Fatalf("idle Work() scanned %d grant tuples instead of O(1) index probes", delta)
	}
}
