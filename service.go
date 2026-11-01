package openplatform

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Service struct {
	Repo    Repository
	Source  Source
	Now     func() time.Time
	Random  io.Reader
	CodeKey []byte
	Issuer  string
}

// Validate checks required dependencies and private protocol configuration.
func (s *Service) Validate() error { return s.ready() }
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func (s *Service) ready() error {
	u, e := url.Parse(s.Issuer)
	if s.Repo == nil || len(s.CodeKey) != 32 || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) random() (string, error) {
	b := make([]byte, 32)
	reader := s.Random
	if reader == nil {
		reader = rand.Reader
	}
	if _, e := io.ReadFull(reader, b); e != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func sameHash(a, b string) bool {
	return len(a) == 64 && len(b) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (s *Service) code(id string) string {
	m := hmac.New(sha256.New, s.CodeKey)
	m.Write([]byte("open-platform-code:" + id))
	return "opc_" + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func validText(v string, max int, empty bool) bool {
	return utf8.ValidString(v) && (empty || strings.TrimSpace(v) != "") && utf8.RuneCountInString(v) <= max && !strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}
func validOwner(v string) bool {
	return v != "" && len(v) <= 2048 && utf8.ValidString(v) && !strings.ContainsFunc(v, unicode.IsControl)
}
func validateScopes(v []string, empty bool) ([]string, error) {
	if len(v) > 7 || (!empty && len(v) == 0) {
		return nil, ErrInput
	}
	out := append([]string{}, v...)
	slices.Sort(out)
	for i, x := range out {
		if !slices.Contains(Scopes, x) || (i > 0 && out[i-1] == x) {
			return nil, ErrInput
		}
	}
	return out, nil
}
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}
func difference(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
func (s *Service) activeOwner(t Transaction, owner string) error {
	if !validOwner(owner) {
		return ErrUnauthenticated
	}
	closed, e := t.Closed(owner)
	if e != nil {
		return e
	}
	if closed {
		return ErrForbidden
	}
	return nil
}
func replay[T any](t Transaction, actor, key, op string, in any, run func() (T, error)) (T, error) {
	var out T
	if key == "" || len(key) > 128 || strings.ContainsFunc(key, unicode.IsControl) {
		return out, ErrInput
	}
	b, e := json.Marshal(struct {
		Operation string
		Input     any
	}{op, in})
	if e != nil {
		return out, ErrInput
	}
	digest := hash(string(b))
	old, body, e := t.Replay(actor, key)
	if e == nil {
		if old != digest {
			return out, ErrConflict
		}
		if json.Unmarshal(body, &out) != nil {
			return out, ErrUnavailable
		}
		return out, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return out, e
	}
	out, e = run()
	if e != nil {
		return out, e
	}
	body, e = json.Marshal(out)
	if e != nil {
		return out, ErrUnavailable
	}
	if e = t.SaveReplay(actor, key, digest, body); e != nil {
		return out, e
	}
	return out, t.Event(actor, op, "", key)
}
func page[T any](items []T, limit int, id func(T) string) Page[T] {
	out := Page[T]{Items: items}
	if len(items) > limit {
		out.Items = items[:limit]
		out.Next = id(items[limit-1])
	}
	return out
}
func pagination(after string, limit int) (int, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 || len(after) > 128 || strings.ContainsFunc(after, unicode.IsControl) {
		return 0, ErrInput
	}
	return limit, nil
}
func lookupError(e error) error {
	if errors.Is(e, ErrNotFound) {
		return ErrUnauthenticated
	}
	return e
}
func policyValid(p Policy) bool {
	return p.GrantSeconds >= 60 && p.GrantSeconds <= 31536000 && p.TokenSeconds >= 60 && p.TokenSeconds <= 3600 && p.TokenSeconds <= p.GrantSeconds && p.DailyQuota >= 1 && p.DailyQuota <= 1000000
}
func validateApp(in *ApplicationInput) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Purpose = strings.TrimSpace(in.Purpose)
	if !validText(in.Name, 80, false) || !validText(in.Purpose, 1000, false) || len(in.RedirectURIs) < 1 || len(in.RedirectURIs) > 10 || (in.ClientType != "public" && in.ClientType != "confidential") {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, raw := range in.RedirectURIs {
		u, e := url.Parse(raw)
		if e != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || seen[raw] || strings.ContainsAny(raw, "\r\n\t") {
			return ErrInput
		}
		seen[raw] = true
	}
	var e error
	in.RequestedScopes, e = validateScopes(in.RequestedScopes, false)
	return e
}
func (s *Service) transaction(ctx context.Context, owner, app string, run func(Transaction) error) error {
	if e := s.ready(); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.Repo.Transaction(ctx, owner, app, run)
}
