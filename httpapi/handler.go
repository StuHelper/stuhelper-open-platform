package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/sdk"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
)

type Handler struct {
	Service      *op.Service
	Authenticate func(*http.Request) (op.Principal, error)
}

type authContextKey struct{}

type requestAuth struct {
	principal op.Principal
	basicApp  string
	secret    string
	basic     bool
}

type serverAdapter struct{ Handler }

var _ sdk.ServerInterface = serverAdapter{}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, e error) {
	code, status := "unavailable", 503
	switch {
	case errors.Is(e, op.ErrInput):
		code, status = "invalid_input", 400
	case errors.Is(e, op.ErrUnauthenticated), errors.Is(e, op.ErrClient):
		code, status = "unauthenticated", 401
	case errors.Is(e, op.ErrForbidden):
		code, status = "forbidden", 403
	case errors.Is(e, op.ErrNotFound):
		code, status = "not_found", 404
	case errors.Is(e, op.ErrConflict):
		code, status = "conflict", 409
	case errors.Is(e, op.ErrQuota):
		code, status = "quota_exceeded", 429
	}
	write(w, status, map[string]string{"code": code})
}
func body(r *http.Request, out any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return op.ErrInput
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return op.ErrInput
	}
	return nil
}
func (h Handler) principal(r *http.Request) (op.Principal, error) {
	if h.Authenticate == nil {
		return op.Principal{}, op.ErrUnauthenticated
	}
	p, e := h.Authenticate(r)
	if e != nil {
		return p, e
	}
	if p.Owner == "" {
		return p, op.ErrUnauthenticated
	}
	return p, nil
}
func authFrom(r *http.Request) requestAuth {
	v, _ := r.Context().Value(authContextKey{}).(requestAuth)
	return v
}
func validateAllowedQuery(rawQuery string, allowed []string) error {
	if rawQuery == "" {
		return nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return op.ErrInput
	}
	for k, v := range values {
		if !slices.Contains(allowed, k) || len(v) != 1 || (k == "limit" && v[0] == "") {
			return op.ErrInput
		}
	}
	return nil
}
func pageArgs(after *sdk.PageAfter, limit *sdk.PageLimit) (string, int) {
	cursor := ""
	if after != nil {
		cursor = *after
	}
	size := 50
	if limit != nil {
		size = *limit
	}
	return cursor, size
}
func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if h.Service == nil {
		failure(w, op.ErrUnavailable)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/open-platform/") || strings.Contains(r.URL.Path, "//") || path.Clean(r.URL.Path) != r.URL.Path {
		failure(w, op.ErrNotFound)
		return
	}
	mux := http.NewServeMux()
	sdk.HandlerWithOptions(serverAdapter{Handler: h}, sdk.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			failure(w, op.ErrInput)
		},
	})
	_, pattern := mux.Handler(r)
	spec, ok := contractRoutes[pattern]
	if !ok {
		failure(w, op.ErrNotFound)
		return
	}
	if pattern == "POST /api/v1/open-platform/token" {
		mux.ServeHTTP(w, r)
		return
	}
	if pattern == "GET /api/v1/open-platform/data/{scope}" {
		if e := validateAllowedQuery(r.URL.RawQuery, spec.queryParams); e != nil {
			failure(w, e)
			return
		}
		mux.ServeHTTP(w, r)
		return
	}

	var auth requestAuth
	noticeRoute := pattern == "GET /api/v1/open-platform/apps/{id}/notices" || pattern == "POST /api/v1/open-platform/apps/{id}/notices/{notice_id}/ack"
	appID, secret, basic := r.BasicAuth()
	if noticeRoute && basic {
		segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/open-platform/"), "/")
		if len(segs) < 3 || appID != segs[1] || secret == "" {
			failure(w, op.ErrUnauthenticated)
			return
		}
		auth = requestAuth{basicApp: appID, secret: secret, basic: true}
	} else {
		p, e := h.principal(r)
		if e != nil {
			failure(w, e)
			return
		}
		auth = requestAuth{principal: p}
	}
	if spec.idempotent && (len(r.Header.Values("Idempotency-Key")) != 1 || r.Header.Get("Idempotency-Key") == "") {
		failure(w, op.ErrInput)
		return
	}
	if e := validateAllowedQuery(r.URL.RawQuery, spec.queryParams); e != nil {
		failure(w, e)
		return
	}
	mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, auth)))
}

func respond(w http.ResponseWriter, result any, err error) {
	if err != nil {
		failure(w, err)
		return
	}
	write(w, http.StatusOK, result)
}

func (s serverAdapter) CreateApplication(w http.ResponseWriter, r *http.Request, params sdk.CreateApplicationParams) {
	var in op.ApplicationInput
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.Apply(r.Context(), authFrom(r).principal, "", params.IdempotencyKey, in)
	respond(w, out, e)
}
func (s serverAdapter) ListOwnApplications(w http.ResponseWriter, r *http.Request, params sdk.ListOwnApplicationsParams) {
	after, limit := pageArgs(params.After, params.Limit)
	out, e := s.Service.Applications(r.Context(), authFrom(r).principal, false, after, limit)
	respond(w, out, e)
}
func (s serverAdapter) ListApplications(w http.ResponseWriter, r *http.Request, params sdk.ListApplicationsParams) {
	after, limit := pageArgs(params.After, params.Limit)
	out, e := s.Service.Applications(r.Context(), authFrom(r).principal, true, after, limit)
	respond(w, out, e)
}
func (s serverAdapter) GetOwnApplication(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath) {
	out, e := s.Service.Application(r.Context(), authFrom(r).principal, id)
	respond(w, out, e)
}
func (s serverAdapter) ResubmitApplication(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath, params sdk.ResubmitApplicationParams) {
	var in op.ApplicationInput
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.Apply(r.Context(), authFrom(r).principal, id, params.IdempotencyKey, in)
	respond(w, out, e)
}
func (s serverAdapter) ReviewApplication(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath, params sdk.ReviewApplicationParams) {
	var in op.ReviewInput
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.Review(r.Context(), authFrom(r).principal, id, params.IdempotencyKey, in)
	respond(w, out, e)
}
func (s serverAdapter) RotateClientCredential(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath, params sdk.RotateClientCredentialParams) {
	var in struct {
		Revision int64 `json:"revision"`
	}
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.RotateCredential(r.Context(), authFrom(r).principal, id, params.IdempotencyKey, in.Revision)
	respond(w, out, e)
}
func (s serverAdapter) PrepareConsent(w http.ResponseWriter, r *http.Request, params sdk.PrepareConsentParams) {
	var in op.ConsentInput
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.PrepareConsent(r.Context(), authFrom(r).principal, params.IdempotencyKey, in)
	respond(w, out, e)
}
func (s serverAdapter) GetConsent(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath) {
	out, e := s.Service.Consent(r.Context(), authFrom(r).principal, id)
	respond(w, out, e)
}
func (s serverAdapter) DecideConsent(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath, params sdk.DecideConsentParams) {
	var in op.ConsentDecision
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.Decide(r.Context(), authFrom(r).principal, id, params.IdempotencyKey, in)
	respond(w, out, e)
}
func (s serverAdapter) ListOwnGrants(w http.ResponseWriter, r *http.Request, params sdk.ListOwnGrantsParams) {
	after, limit := pageArgs(params.After, params.Limit)
	out, e := s.Service.Grants(r.Context(), authFrom(r).principal, after, limit)
	respond(w, out, e)
}
func (s serverAdapter) RevokeScopes(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath, params sdk.RevokeScopesParams) {
	var in op.RevokeInput
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.Revoke(r.Context(), authFrom(r).principal, id, params.IdempotencyKey, in)
	respond(w, out, e)
}
func (s serverAdapter) ListNotices(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath, params sdk.ListNoticesParams) {
	auth := authFrom(r)
	if auth.basic && auth.basicApp != id {
		failure(w, op.ErrUnauthenticated)
		return
	}
	after, limit := pageArgs(params.After, params.Limit)
	out, e := s.Service.Notices(r.Context(), auth.principal, id, auth.secret, after, limit)
	respond(w, out, e)
}
func (s serverAdapter) AcknowledgeNotice(w http.ResponseWriter, r *http.Request, id sdk.ResourceIdPath, noticeID sdk.NoticeIdPath, params sdk.AcknowledgeNoticeParams) {
	auth := authFrom(r)
	if auth.basic && auth.basicApp != id {
		failure(w, op.ErrUnauthenticated)
		return
	}
	var in op.Acknowledgement
	if e := body(r, &in); e != nil {
		failure(w, e)
		return
	}
	out, e := s.Service.Acknowledge(r.Context(), auth.principal, id, auth.secret, noticeID, params.IdempotencyKey, in)
	respond(w, out, e)
}
func (s serverAdapter) ExchangeCode(w http.ResponseWriter, r *http.Request) {
	bad := func(code string, status int) { write(w, status, map[string]string{"error": code}) }
	if len(r.URL.RawQuery) != 0 || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil {
		bad("invalid_request", 400)
		return
	}
	allowed := []string{"grant_type", "client_id", "redirect_uri", "code", "code_verifier"}
	for k, v := range r.PostForm {
		if !slices.Contains(allowed, k) || len(v) != 1 {
			bad("invalid_request", 400)
			return
		}
	}
	id, secret, basic := r.BasicAuth()
	client := r.PostForm.Get("client_id")
	if basic && (id != client || secret == "") {
		bad("invalid_client", 401)
		return
	}
	if !basic && r.Header.Get("Authorization") != "" {
		bad("invalid_client", 401)
		return
	}
	result, e := s.Service.Exchange(r.Context(), op.TokenInput{GrantType: r.PostForm.Get("grant_type"), ClientID: client, RedirectURI: r.PostForm.Get("redirect_uri"), Code: r.PostForm.Get("code"), Verifier: r.PostForm.Get("code_verifier"), ClientSecret: secret})
	if e != nil {
		if errors.Is(e, op.ErrClient) {
			w.Header().Set("WWW-Authenticate", `Basic realm="open-platform"`)
			bad("invalid_client", 401)
		} else if errors.Is(e, op.ErrInput) {
			bad("invalid_request", 400)
		} else if errors.Is(e, op.ErrUnavailable) {
			bad("temporarily_unavailable", 503)
		} else {
			bad("invalid_grant", 400)
		}
		return
	}
	write(w, 200, result)
}
func (s serverAdapter) ReadAuthorizedData(w http.ResponseWriter, r *http.Request, scope sdk.ScopePath, params sdk.ReadAuthorizedDataParams) {
	sc := string(scope)
	allowed := []string{}
	switch sc {
	case "schedule":
		allowed = []string{"term_id", "after", "limit"}
	case "catalog":
		allowed = []string{"id", "kind", "query", "term_id", "after", "limit"}
	case "public_reviews":
		allowed = []string{"id", "kind", "term_id", "target_id", "after", "limit"}
	}
	if e := validateAllowedQuery(r.URL.RawQuery, allowed); e != nil {
		failure(w, e)
		return
	}
	limit := 50
	if params.Limit != nil {
		if *params.Limit < 1 || *params.Limit > 100 {
			failure(w, op.ErrInput)
			return
		}
		limit = *params.Limit
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		failure(w, op.ErrUnauthenticated)
		return
	}
	out, e := s.Service.Read(r.Context(), strings.TrimPrefix(auth, "Bearer "), sc, op.Query{
		ID:       derefString(params.Id),
		Kind:     derefString(params.Kind),
		Query:    derefString(params.Query),
		TermID:   derefString(params.TermId),
		TargetID: derefString(params.TargetId),
		After:    derefString(params.After),
		Limit:    limit,
	})
	respond(w, out, e)
}
