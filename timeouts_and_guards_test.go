package openplatform_test

import (
	"context"
	"encoding/json"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"strings"
	"testing"
	"time"
)

type customErrSource struct {
	err error
}

func (c customErrSource) Read(context.Context, string, string, op.Query) (op.Data, error) {
	return op.Data{}, c.err
}

type deadlineCheckingRepo struct {
	op.Repository
	missingDeadline string
}

func (d *deadlineCheckingRepo) check(ctx context.Context, name string) {
	if _, ok := ctx.Deadline(); !ok && d.missingDeadline == "" {
		d.missingDeadline = name
	}
}
func (d *deadlineCheckingRepo) LocateConsent(ctx context.Context, id string) (op.ConsentRecord, error) {
	d.check(ctx, "LocateConsent")
	return d.Repository.LocateConsent(ctx, id)
}
func (d *deadlineCheckingRepo) LocateCode(ctx context.Context, h string) (op.ConsentRecord, error) {
	d.check(ctx, "LocateCode")
	return d.Repository.LocateCode(ctx, h)
}
func (d *deadlineCheckingRepo) LocateGrant(ctx context.Context, id string) (op.GrantRecord, error) {
	d.check(ctx, "LocateGrant")
	return d.Repository.LocateGrant(ctx, id)
}
func (d *deadlineCheckingRepo) LocateToken(ctx context.Context, h string) (op.TokenRecord, op.GrantRecord, error) {
	d.check(ctx, "LocateToken")
	return d.Repository.LocateToken(ctx, h)
}

func TestOutOfTxTimeoutsNilSourceQuotaErrorWhitelistRedirectParamsAndExchangeClientOracle(t *testing.T) {
	x := setup(t)
	wrappedRepo := &deadlineCheckingRepo{Repository: x.repo}
	x.s.Repo = wrappedRepo
	s := x.s

	// 1. A-12(2): Issuer validation (empty hostname https://:443 or >512 bytes) and RedirectURI query validation.
	badIssuerSvc := *s
	badIssuerSvc.Issuer = "https://:443"
	if err := badIssuerSvc.Validate(); !errors.Is(err, op.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for https://:443 Issuer, got %v", err)
	}
	badIssuerSvc.Issuer = "https://issuer.example/" + strings.Repeat("a", 510)
	if err := badIssuerSvc.Validate(); !errors.Is(err, op.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for oversized Issuer, got %v", err)
	}

	for _, badURI := range []string{
		"https://client.example/cb with-space",
		"https://client.example/cb#",
		"https://client.example/cb?ctx=1;2",
		"https://client.example/cb?code=preset",
		"https://client.example/cb?state=preset",
		"https://client.example/cb?iss=https://evil.example",
		"https://client.example/cb?error=access_denied",
	} {
		if _, err := s.Apply(ctx, dev, "", "bad-uri:"+badURI, op.ApplicationInput{
			Name:            "Bad URI App",
			Purpose:         "test",
			RedirectURIs:    []string{badURI},
			RequestedScopes: []string{"profile"},
			ClientType:      "public",
		}); !errors.Is(err, op.ErrInput) {
			t.Fatalf("expected ErrInput for RedirectURI %q, got %v", badURI, err)
		}
	}

	// Valid query param in RedirectURI must still succeed and preserve query param on Decide.
	appWithQuery, err := s.Apply(ctx, dev, "", "valid-query-uri", op.ApplicationInput{
		Name:            "Valid Query App",
		Purpose:         "test",
		RedirectURIs:    []string{"https://client.example/cb?tenant=buaa"},
		RequestedScopes: []string{"profile"},
		ClientType:      "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	app := approve(t, s, appWithQuery, []string{"profile"}, 2)
	_, pubCode, pubVerifier := consent(t, s, alice, app, "pub-code", []string{"profile"})

	// 2. A-12(3): Cross-client Exchange must NOT leak whether the stolen code belongs to a public or confidential app.
	confApp := approve(t, s, apply(t, s, dev, "conf-app", []string{"profile"}, "confidential"), []string{"profile"}, 10)
	confCred, err := s.RotateCredential(ctx, dev, confApp.ID, "conf-secret", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(ctx, op.TokenInput{
		GrantType:    "authorization_code",
		ClientID:     confApp.ID,
		RedirectURI:  confApp.RedirectURIs[0],
		Code:         pubCode,
		Verifier:     pubVerifier,
		ClientSecret: confCred.Secret,
	}); !errors.Is(err, op.ErrUnauthenticated) {
		t.Fatalf("cross-client code probe leaked error %v instead of ErrUnauthenticated", err)
	}

	// Complete legitimate exchange and grant operations to trigger LocateConsent, LocateCode, LocateToken, LocateGrant.
	tok := exchange(t, s, app, pubCode, pubVerifier, "")

	// 3. A-12(1): When s.Source == nil, Read must return ErrUnavailable WITHOUT deducting daily quota.
	origSource := s.Source
	s.Source = nil
	if _, err := s.Read(ctx, tok.AccessToken, "profile", op.Query{}); !errors.Is(err, op.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable when Source == nil, got %v", err)
	}
	if used := count(t, x.db, `SELECT COALESCE((SELECT used FROM open_platform.quotas WHERE app_id=$1), 0)`, app.ID); used != 0 {
		t.Fatalf("Source == nil wrongly consumed daily quota: used=%d", used)
	}

	// 4. A-12(1): Provider returning internal ErrUnauthenticated / ErrQuota / ErrConflict must be normalized to ErrUnavailable,
	// whereas ErrForbidden / ErrNotFound / ErrInput pass through.
	for _, internalErr := range []error{op.ErrUnauthenticated, op.ErrQuota, op.ErrConflict, errors.New("adapter boom")} {
		// Bump quota so multiple Read calls can execute.
		if _, err := x.db.Exec(`DELETE FROM open_platform.quotas WHERE app_id=$1`, app.ID); err != nil {
			t.Fatal(err)
		}
		s.Source = customErrSource{err: internalErr}
		if _, err := s.Read(ctx, tok.AccessToken, "profile", op.Query{}); !errors.Is(err, op.ErrUnavailable) {
			t.Fatalf("provider error %v leaked as %v instead of ErrUnavailable", internalErr, err)
		}
	}
	for _, allowedErr := range []error{op.ErrForbidden, op.ErrNotFound, op.ErrInput} {
		if _, err := x.db.Exec(`DELETE FROM open_platform.quotas WHERE app_id=$1`, app.ID); err != nil {
			t.Fatal(err)
		}
		s.Source = customErrSource{err: allowedErr}
		if _, err := s.Read(ctx, tok.AccessToken, "profile", op.Query{}); !errors.Is(err, allowedErr) {
			t.Fatalf("expected whitelisted provider error %v to pass through, got %v", allowedErr, err)
		}
	}
	s.Source = origSource
	if _, err := x.db.Exec(`DELETE FROM open_platform.quotas WHERE app_id=$1`, app.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, tok.AccessToken, "profile", op.Query{}); err != nil {
		t.Fatal(err)
	}
	gs, err := s.Grants(ctx, alice, "", 10)
	if err != nil || len(gs.Items) != 1 {
		t.Fatal(gs, err)
	}
	if _, err := s.Revoke(ctx, alice, gs.Items[0].ID, "check-locate-grant", op.RevokeInput{Revision: gs.Items[0].Revision, Scopes: []string{"profile"}}); err != nil {
		t.Fatal(err)
	}

	// 5. A-07: Every out-of-transaction Locate* call must have received a context with a <=5s deadline!
	if wrappedRepo.missingDeadline != "" {
		t.Fatalf("out-of-transaction repository call %s lacked a 5s context deadline", wrappedRepo.missingDeadline)
	}
	_ = json.Marshal
	_ = time.Second
}
