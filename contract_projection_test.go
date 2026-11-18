package openplatform_test

import (
	"encoding/json"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOpenAPIConstraintsUnexpectedQueryRejectionAndOP05ContentAdmission(t *testing.T) {
	x := setup(t)
	s := x.s

	// 1. Verify embedded OpenAPI contract matches runtime constraints (Profile maxLength 20/120, ConsentInput.state minLength 16, minItems/uniqueItems).
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					MinLength   *int  `json:"minLength"`
					MaxLength   *int  `json:"maxLength"`
					MinItems    *int  `json:"minItems"`
					UniqueItems *bool `json:"uniqueItems"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(op.OpenAPI(), &spec); err != nil {
		t.Fatal(err)
	}
	prof := spec.Components.Schemas["Profile"].Properties
	if prof["nickname"].MaxLength == nil || *prof["nickname"].MaxLength != 20 || prof["bio"].MaxLength == nil || *prof["bio"].MaxLength != 120 {
		t.Fatalf("OpenAPI Profile maxLength mismatch: nickname=%v bio=%v", prof["nickname"].MaxLength, prof["bio"].MaxLength)
	}
	consentIn := spec.Components.Schemas["ConsentInput"].Properties
	if consentIn["state"].MinLength == nil || *consentIn["state"].MinLength != 16 {
		t.Fatalf("OpenAPI ConsentInput.state missing minLength 16: %v", consentIn["state"].MinLength)
	}
	if consentIn["scope"].MinItems == nil || *consentIn["scope"].MinItems != 1 || consentIn["scope"].UniqueItems == nil || !*consentIn["scope"].UniqueItems {
		t.Fatalf("OpenAPI ConsentInput.scope missing minItems=1 or uniqueItems=true")
	}

	// 2. Verify non-list routes reject undeclared ?after=&limit= query parameters with 400 invalid_input.
	app := approve(t, s, apply(t, s, dev, "contract-app", []string{"profile", "schools", "schedule", "catalog", "public_reviews"}, "public"), []string{"profile", "schools", "schedule", "catalog", "public_reviews"}, 100)
	h := httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (op.Principal, error) {
			if r.Header.Get("Authorization") == "Bearer session-dev" {
				return dev, nil
			}
			return op.Principal{}, op.ErrUnauthenticated
		},
	}
	reqGetSingle := httptest.NewRequest("GET", "/api/v1/open-platform/apps/"+app.ID+"?limit=10", nil)
	reqGetSingle.Header.Set("Authorization", "Bearer session-dev")
	wGetSingle := httptest.NewRecorder()
	h.ServeHTTP(wGetSingle, reqGetSingle)
	if wGetSingle.Code != 400 {
		t.Fatalf("GET /apps/{id}?limit=10 expected 400, got %d %s", wGetSingle.Code, wGetSingle.Body.String())
	}
	reqPostQuery := httptest.NewRequest("POST", "/api/v1/open-platform/apps?after=abc", strings.NewReader(`{"name":"Q","purpose":"p","redirect_uris":["https://x.example/cb"],"requested_scopes":["profile"],"client_type":"public"}`))
	reqPostQuery.Header.Set("Authorization", "Bearer session-dev")
	reqPostQuery.Header.Set("Content-Type", "application/json")
	reqPostQuery.Header.Set("Idempotency-Key", "post-with-query")
	wPostQuery := httptest.NewRecorder()
	h.ServeHTTP(wPostQuery, reqPostQuery)
	if wPostQuery.Code != 400 {
		t.Fatalf("POST /apps?after=abc expected 400, got %d %s", wPostQuery.Code, wPostQuery.Body.String())
	}

	// 3. OP-05: User authorizes catalog, public_reviews, profile, schools, schedule;
	// when content admission is unsatisfied (source state == 1), catalog and public_reviews are denied with 403 ErrForbidden,
	// while non-community scopes remain accessible; once admitted, all scopes project valid non-null JSON arrays.
	tok := tokenFor(t, s, alice, app, "op05-grant", []string{"profile", "schools", "schedule", "catalog", "public_reviews"})
	for _, sc := range []string{"schools", "schedule", "catalog", "public_reviews"} {
		req := httptest.NewRequest("GET", "/api/v1/open-platform/data/"+sc, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 || strings.Contains(w.Body.String(), ":null") {
			t.Fatalf("GET /data/%s expected 200 without null slices, got %d %s", sc, w.Code, w.Body.String())
		}
		if sc == "schedule" && strings.Contains(w.Body.String(), "dropped-course") {
			t.Fatalf("inactive enrollment leaked in schedule response: %s", w.Body.String())
		}
	}

	x.source.state.Store(1)
	for _, gated := range []string{"catalog", "public_reviews"} {
		if _, err := s.Read(ctx, tok.AccessToken, gated, op.Query{}); !errors.Is(err, op.ErrForbidden) {
			t.Fatalf("OP-05 expected ErrForbidden on %s when content admission fails, got %v", gated, err)
		}
		req := httptest.NewRequest("GET", "/api/v1/open-platform/data/"+gated, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("OP-05 HTTP expected 403 on %s, got %d %s", gated, w.Code, w.Body.String())
		}
	}
	// Profile and schedule are not community content admission scopes and continue to succeed when only community admission is unsatisfied.
	if _, err := s.Read(ctx, tok.AccessToken, "profile", op.Query{}); err != nil {
		t.Fatalf("expected profile to remain readable during OP-05 content admission denial, got %v", err)
	}
	_ = time.Second
}
