package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

type Handler struct {
	Service      *op.Service
	Authenticate func(*http.Request) (op.Principal, error)
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (h Handler) failure(w http.ResponseWriter, e error) {
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
		retryAfter := 86400
		if h.Service != nil {
			retryAfter = h.Service.RetryAfterSeconds()
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	write(w, status, op.Problem{Code: code, Reason: op.ErrorReason(e)})
}
func validMediaType(r *http.Request, expected string) bool {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, params, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != expected {
		return false
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}
	return true
}
func body(r *http.Request, out any) error {
	if !validMediaType(r, "application/json") {
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
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if h.Service == nil {
		h.failure(w, op.ErrUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/open-platform/")
	if path == r.URL.Path || strings.Contains(path, "//") {
		h.failure(w, op.ErrNotFound)
		return
	}
	parts := strings.Split(path, "/")
	if path == "token" && r.Method == "POST" {
		h.token(w, r)
		return
	}
	if len(parts) == 2 && parts[0] == "data" && r.Method == "GET" {
		h.data(w, r, parts[1])
		return
	}
	appID, secret, basic := r.BasicAuth()
	noticeRoute := len(parts) >= 3 && parts[0] == "apps" && parts[2] == "notices"
	var p op.Principal
	var e error
	if noticeRoute && basic {
		if appID != parts[1] || secret == "" {
			h.failure(w, op.ErrUnauthenticated)
			return
		}
	} else {
		p, e = h.principal(r)
		if e != nil {
			h.failure(w, e)
			return
		}
	}
	var result any
	key := r.Header.Get("Idempotency-Key")
	if r.Method == "POST" && len(r.Header.Values("Idempotency-Key")) != 1 {
		h.failure(w, op.ErrInput)
		return
	}
	noQuery := func() bool {
		if len(r.URL.RawQuery) != 0 {
			e = op.ErrInput
			return false
		}
		return true
	}
	switch {
	case path == "apps" && r.Method == "POST":
		if noQuery() {
			var in op.ApplicationInput
			if e = body(r, &in); e == nil {
				result, e = h.Service.Apply(r.Context(), p, "", key, in)
			}
		}
	case path == "apps" && r.Method == "GET":
		var after string
		var limit int
		if after, limit, e = queryPage(r); e == nil {
			result, e = h.Service.Applications(r.Context(), p, false, after, limit)
		}
	case path == "admin/apps" && r.Method == "GET":
		var f op.AdminAppFilter
		f, e = queryAdminApps(r)
		if e == nil {
			result, e = h.Service.AdminApplications(r.Context(), p, f)
		}
	case len(parts) == 3 && parts[0] == "admin" && parts[1] == "apps" && r.Method == "GET":
		if noQuery() {
			result, e = h.Service.AdminApplication(r.Context(), p, parts[2])
		}
	case path == "admin/notices/overdue" && r.Method == "GET":
		var after string
		var days, limit int
		days, after, limit, e = queryOverduePage(r)
		if e == nil {
			result, e = h.Service.OverdueNoticeApplications(r.Context(), p, days, after, limit)
		}
	case len(parts) == 2 && parts[0] == "apps" && r.Method == "GET":
		if noQuery() {
			result, e = h.Service.Application(r.Context(), p, parts[1])
		}
	case len(parts) == 3 && parts[0] == "apps" && parts[2] == "submit" && r.Method == "POST":
		if noQuery() {
			var in op.ApplicationInput
			if e = body(r, &in); e == nil {
				result, e = h.Service.Apply(r.Context(), p, parts[1], key, in)
			}
		}
	case len(parts) == 3 && parts[0] == "apps" && parts[2] == "archive" && r.Method == "POST":
		var in struct {
			Revision int64 `json:"revision"`
		}
		if noQuery() {
			if e = body(r, &in); e == nil {
				result, e = h.Service.Archive(r.Context(), p, parts[1], key, in.Revision)
			}
		}
	case len(parts) == 4 && parts[0] == "admin" && parts[1] == "apps" && parts[3] == "review" && r.Method == "POST":
		if noQuery() {
			var in op.ReviewInput
			if e = body(r, &in); e == nil {
				result, e = h.Service.Review(r.Context(), p, parts[2], key, in)
			}
		}
	case len(parts) == 3 && parts[0] == "apps" && parts[2] == "credential" && r.Method == "POST":
		if noQuery() {
			var in struct {
				Revision int64 `json:"revision"`
			}
			if e = body(r, &in); e == nil {
				result, e = h.Service.RotateCredential(r.Context(), p, parts[1], key, in.Revision)
			}
		}
	case path == "consents" && r.Method == "POST":
		if noQuery() {
			var in op.ConsentInput
			if e = body(r, &in); e == nil {
				result, e = h.Service.PrepareConsent(r.Context(), p, key, in)
			}
		}
	case len(parts) == 2 && parts[0] == "consents" && r.Method == "GET":
		if noQuery() {
			result, e = h.Service.Consent(r.Context(), p, parts[1])
		}
	case len(parts) == 3 && parts[0] == "consents" && parts[2] == "decision" && r.Method == "POST":
		if noQuery() {
			var in op.ConsentDecision
			if e = body(r, &in); e == nil {
				result, e = h.Service.Decide(r.Context(), p, parts[1], key, in)
			}
		}
	case path == "grants" && r.Method == "GET":
		var after string
		var limit int
		var state string
		state, after, limit, e = queryGrantsPage(r)
		if e == nil {
			result, e = h.Service.ListGrants(r.Context(), p, state, after, limit)
		}
	case len(parts) == 3 && parts[0] == "grants" && parts[2] == "revoke" && r.Method == "POST":
		if noQuery() {
			var in op.RevokeInput
			if e = body(r, &in); e == nil {
				result, e = h.Service.Revoke(r.Context(), p, parts[1], key, in)
			}
		}
	case noticeRoute && len(parts) == 3 && r.Method == "GET":
		var after string
		var limit int
		var pendingAck bool
		pendingAck, after, limit, e = queryNoticesPage(r)
		if e == nil {
			result, e = h.Service.ListNotices(r.Context(), p, parts[1], secret, pendingAck, after, limit)
		}
	case noticeRoute && len(parts) == 5 && parts[4] == "ack" && r.Method == "POST":
		if noQuery() {
			var in op.Acknowledgement
			if e = body(r, &in); e == nil {
				result, e = h.Service.Acknowledge(r.Context(), p, parts[1], secret, parts[3], key, in)
			}
		}
	default:
		e = op.ErrNotFound
	}
	if e != nil {
		h.failure(w, e)
		return
	}
	write(w, 200, result)
}
func queryPage(r *http.Request) (string, int, error) {
	for k, v := range r.URL.Query() {
		if !slices.Contains([]string{"after", "limit"}, k) || len(v) != 1 {
			return "", 0, op.ErrInput
		}
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil {
			return "", 0, op.ErrInput
		}
		limit = n
	}
	return r.URL.Query().Get("after"), limit, nil
}
func queryGrantsPage(r *http.Request) (string, string, int, error) {
	for k, v := range r.URL.Query() {
		if !slices.Contains([]string{"state", "after", "limit"}, k) || len(v) != 1 {
			return "", "", 0, op.ErrInput
		}
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil {
			return "", "", 0, op.ErrInput
		}
		limit = n
	}
	return r.URL.Query().Get("state"), r.URL.Query().Get("after"), limit, nil
}
func (h Handler) token(w http.ResponseWriter, r *http.Request) {
	bad := func(code string, status int) { write(w, status, map[string]string{"error": code}) }
	if len(r.URL.RawQuery) != 0 || !validMediaType(r, "application/x-www-form-urlencoded") || r.ParseForm() != nil {
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
	result, e := h.Service.Exchange(r.Context(), op.TokenInput{GrantType: r.PostForm.Get("grant_type"), ClientID: client, RedirectURI: r.PostForm.Get("redirect_uri"), Code: r.PostForm.Get("code"), Verifier: r.PostForm.Get("code_verifier"), ClientSecret: secret})
	if e != nil {
		if errors.Is(e, op.ErrClient) {
			w.Header().Set("WWW-Authenticate", `Basic realm="open-platform"`)
			bad("invalid_client", 401)
		} else if errors.Is(e, op.ErrInput) {
			bad("invalid_request", 400)
		} else if errors.Is(e, op.ErrUnavailable) || errors.Is(e, op.ErrConflict) || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
			bad("temporarily_unavailable", 503)
		} else {
			bad("invalid_grant", 400)
		}
		return
	}
	write(w, 200, result)
}
func (h Handler) data(w http.ResponseWriter, r *http.Request, scope string) {
	allowed := []string{}
	switch scope {
	case "schedule":
		allowed = []string{"term_id", "after", "limit"}
	case "catalog":
		allowed = []string{"id", "kind", "query", "term_id", "after", "limit"}
	case "public_reviews":
		allowed = []string{"id", "kind", "term_id", "target_id", "after", "limit"}
	}
	for k, v := range r.URL.Query() {
		if !slices.Contains(allowed, k) || len(v) != 1 {
			h.failure(w, op.ErrInput)
			return
		}
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 100 {
			h.failure(w, op.ErrInput)
			return
		}
		limit = n
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		h.failure(w, op.ErrUnauthenticated)
		return
	}
	q := r.URL.Query()
	out, qw, e := h.Service.ReadWithQuota(r.Context(), strings.TrimPrefix(auth, "Bearer "), scope, op.Query{ID: q.Get("id"), Kind: q.Get("kind"), Query: q.Get("query"), TermID: q.Get("term_id"), TargetID: q.Get("target_id"), After: q.Get("after"), Limit: limit})
	if qw.Set {
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(qw.Limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(qw.Remaining))
	}
	if e != nil {
		h.failure(w, e)
		return
	}
	write(w, 200, out)
}

func queryAdminApps(r *http.Request) (op.AdminAppFilter, error) {
	for k, v := range r.URL.Query() {
		if !slices.Contains([]string{"state", "owner", "after", "limit"}, k) || len(v) != 1 {
			return op.AdminAppFilter{}, op.ErrInput
		}
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil {
			return op.AdminAppFilter{}, op.ErrInput
		}
		limit = n
	}
	q := r.URL.Query()
	return op.AdminAppFilter{State: q.Get("state"), Owner: q.Get("owner"), After: q.Get("after"), Limit: limit}, nil
}

func queryOverduePage(r *http.Request) (int, string, int, error) {
	for k, v := range r.URL.Query() {
		if !slices.Contains([]string{"older_than_days", "after", "limit"}, k) || len(v) != 1 {
			return 0, "", 0, op.ErrInput
		}
	}
	days := 7
	if raw := r.URL.Query().Get("older_than_days"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 365 {
			return 0, "", 0, op.ErrInput
		}
		days = n
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil {
			return 0, "", 0, op.ErrInput
		}
		limit = n
	}
	return days, r.URL.Query().Get("after"), limit, nil
}

func queryNoticesPage(r *http.Request) (bool, string, int, error) {
	for k, v := range r.URL.Query() {
		if !slices.Contains([]string{"pending_ack", "after", "limit"}, k) || len(v) != 1 {
			return false, "", 0, op.ErrInput
		}
	}
	pendingAck := false
	if raw := r.URL.Query().Get("pending_ack"); raw != "" {
		b, e := strconv.ParseBool(raw)
		if e != nil || (raw != "true" && raw != "false") {
			return false, "", 0, op.ErrInput
		}
		pendingAck = b
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil {
			return false, "", 0, op.ErrInput
		}
		limit = n
	}
	return pendingAck, r.URL.Query().Get("after"), limit, nil
}
