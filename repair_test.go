package openplatform_test

import (
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"strings"
	"testing"
	"time"
)

func TestCodeReplayRevokesIssuedTokenAndProfileIdentifiersArePairwise(t *testing.T) {
	x := setup(t)
	a := approve(t, x.s, apply(t, x.s, dev, "first", []string{"profile"}, "public"), []string{"profile"}, 100)
	b := approve(t, x.s, apply(t, x.s, dev, "second", []string{"profile"}, "public"), []string{"profile"}, 100)
	_, code, verifier := consent(t, x.s, alice, a, "first", []string{"profile"})
	first := exchange(t, x.s, a, code, verifier, "")
	second := tokenFor(t, x.s, alice, b, "second", []string{"profile"})
	one, e := x.s.Read(ctx, first.AccessToken, "profile", op.Query{})
	if e != nil {
		t.Fatal(e)
	}
	two, e := x.s.Read(ctx, second.AccessToken, "profile", op.Query{})
	if e != nil || one.Profile.ID == two.Profile.ID || one.Profile.ID != one.Subject || two.Profile.ID != two.Subject || one.Profile.ID == "public-alice" {
		t.Fatal(one, two, e)
	}
	in := op.TokenInput{GrantType: "authorization_code", ClientID: a.ID, RedirectURI: a.RedirectURIs[0], Code: code, Verifier: strings.Repeat("b", 43)}
	if _, e = x.s.Exchange(ctx, in); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	if _, e = x.s.Read(ctx, first.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal("invalid proof revoked another token", e)
	}
	in.Verifier = verifier
	if _, e = x.s.Exchange(ctx, in); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal(e)
	}
	if _, e = x.s.Read(ctx, first.AccessToken, "profile", op.Query{}); !errors.Is(e, op.ErrUnauthenticated) {
		t.Fatal("replayed code token still active", e)
	}
	if _, e = x.s.Read(ctx, second.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal("unrelated application revoked", e)
	}
}

func TestCleanupIsBoundedPreservesLiveDataAndRollsBackFailures(t *testing.T) {
	x := setup(t)
	now := x.s.Now()
	a := approve(t, x.s, apply(t, x.s, dev, "app", []string{"profile"}, "public"), []string{"profile"}, 100)
	token := tokenFor(t, x.s, alice, a, "live", []string{"profile"})
	for _, q := range []string{
		`INSERT INTO open_platform.requests(actor,key,digest,result,created_at) SELECT 'expired',n::text,'hash','{}',$1::timestamptz-interval '25 hours' FROM generate_series(1,5) n`,
		`INSERT INTO open_platform.events(actor,kind,object_id,operation,created_at) SELECT 'expired','synthetic','object',n::text,$1::timestamptz-interval '13 months' FROM generate_series(1,5) n`,
	} {
		if _, e := x.db.Exec(q, now); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := x.db.Exec(`CREATE FUNCTION open_platform.reject_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$;CREATE TRIGGER reject_cleanup BEFORE DELETE ON open_platform.events FOR EACH ROW EXECUTE FUNCTION open_platform.reject_cleanup()`); e != nil {
		t.Fatal(e)
	}
	if _, e := x.s.Cleanup(ctx, 2); e == nil {
		t.Fatal("cleanup failure hidden")
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.requests WHERE actor='expired'`); n != 5 {
		t.Fatal("partial cleanup committed", n)
	}
	if _, e := x.db.Exec(`DROP TRIGGER reject_cleanup ON open_platform.events`); e != nil {
		t.Fatal(e)
	}
	n, e := x.s.Cleanup(ctx, 2)
	if e != nil || n != 4 {
		t.Fatal(n, e)
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.requests WHERE actor='expired'`); n != 3 {
		t.Fatal("unbounded cleanup", n)
	}
	if _, e = x.s.Read(ctx, token.AccessToken, "profile", op.Query{}); e != nil {
		t.Fatal("live token removed", e)
	}
	x.clock.Add(int64((25 * time.Hour) / time.Second))
	for range 5 {
		if _, e = x.s.Cleanup(ctx, 100); e != nil {
			t.Fatal(e)
		}
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.tokens`); n != 0 {
		t.Fatal("expired token retained", n)
	}
	if n := count(t, x.db, `SELECT count(*) FROM open_platform.consents`); n != 0 {
		t.Fatal("expired consent retained", n)
	}
	if _, e = x.s.Cleanup(ctx, 101); !errors.Is(e, op.ErrInput) {
		t.Fatal("unbounded batch accepted", e)
	}
}

func TestQQTiersRequireIndependentApprovalConsentAndTrustedSource(t *testing.T) {
	x := setup(t)
	scopes := []string{"qq_binding_status", "qq_binding_details"}
	a := apply(t, x.s, dev, "qq", scopes, "public")
	a = approve(t, x.s, a, []string{"qq_binding_status"}, 100)
	// An approved status scope cannot be used to request the number tier.
	_, err := x.s.PrepareConsent(ctx, alice, "unapproved", op.ConsentInput{ClientID: a.ID, RedirectURI: a.RedirectURIs[0], State: "state-bound-to-test-browser", Scopes: []string{"qq_binding_details"}, Challenge: strings.Repeat("A", 43), Method: "S256"})
	if !errors.Is(err, op.ErrForbidden) {
		t.Fatal(err)
	}
	a = approve(t, x.s, a, scopes, 100)
	token := tokenFor(t, x.s, alice, a, "status", []string{"qq_binding_status"})
	data, err := x.s.Read(ctx, token.AccessToken, "qq_binding_status", op.Query{})
	if err != nil || data.QQBinding == nil || !data.QQBinding.Bound || data.QQBinding.Number != "" {
		t.Fatal(data, err)
	}
	if _, err = x.s.Read(ctx, token.AccessToken, "qq_binding_details", op.Query{}); !errors.Is(err, op.ErrForbidden) {
		t.Fatal(err)
	}
	c, code, verifier := consent(t, x.s, bob, a, "details", []string{"qq_binding_details"})
	if len(c.QQTiers) != 1 || c.QQTiers[0] != "binding_status_and_number" {
		t.Fatal(c)
	}
	details := exchange(t, x.s, a, code, verifier, "")
	data, err = x.s.Read(ctx, details.AccessToken, "qq_binding_details", op.Query{})
	if err != nil || data.QQBinding == nil || data.QQBinding.Number != "123456" {
		t.Fatal(data, err)
	}
	if _, err = x.s.Read(ctx, details.AccessToken, "qq_binding_status", op.Query{}); !errors.Is(err, op.ErrForbidden) {
		t.Fatal(err)
	}
	x.source.state.Store(2)
	for _, v := range []struct{ token, scope string }{{token.AccessToken, "qq_binding_status"}, {details.AccessToken, "qq_binding_details"}} {
		if _, err = x.s.Read(ctx, v.token, v.scope, op.Query{}); !errors.Is(err, op.ErrUnavailable) {
			t.Fatal(v.scope, err)
		}
	}
}
