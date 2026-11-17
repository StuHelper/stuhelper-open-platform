package openplatform

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"
)

func stringRevision(v int64) string { return strconv.FormatInt(v, 10) }
func (s *Service) authorizeToken(t Transaction, h, scope string, count bool) (GrantRecord, QuotaWindow, error) {
	var empty GrantRecord
	var qw QuotaWindow
	v, e := t.Token(h)
	if e != nil {
		return empty, qw, lookupError(e)
	}
	g, e := t.Grant(v.GrantID)
	if e != nil {
		return empty, qw, lookupError(e)
	}
	a, e := t.App(g.View.AppID)
	if e != nil {
		return empty, qw, e
	}
	reason, e := s.grantReason(t, g, a)
	if e != nil {
		return empty, qw, e
	}
	if reason != "" || !s.now().Before(v.ExpiresAt) || v.GrantRevision != g.View.Revision || v.AppRevision != a.View.Revision {
		return empty, qw, ErrUnauthenticated
	}
	if !slices.Contains(g.View.Scopes, scope) || !slices.Contains(a.View.ApprovedScopes, scope) {
		return empty, qw, ErrForbidden
	}
	if count {
		used, e := t.Quota(a.View.ID, s.now().Format("2006-01-02"), a.View.Policy.DailyQuota)
		rem := a.View.Policy.DailyQuota - used
		if rem < 0 {
			rem = 0
		}
		qw = QuotaWindow{Set: true, Limit: a.View.Policy.DailyQuota, Remaining: rem}
		if e != nil {
			return empty, qw, e
		}
		if e = t.Event(g.Owner, "data_requested", g.View.ID, scope); e != nil {
			return empty, qw, e
		}
	}
	return g, qw, nil
}
func (s *Service) Read(ctx context.Context, token, scope string, q Query) (Data, error) {
	out, _, e := s.ReadWithQuota(ctx, token, scope, q)
	return out, e
}
func (s *Service) ReadWithQuota(ctx context.Context, token, scope string, q Query) (Data, QuotaWindow, error) {
	var out Data
	var qw QuotaWindow
	if e := s.ready(); e != nil {
		return out, qw, e
	}
	if !slices.Contains(Scopes, scope) || q.Limit < 0 || q.Limit > 100 {
		return out, qw, ErrInput
	}
	if !strings.HasPrefix(token, "op_") || len(token) > 100 {
		return out, qw, ErrUnauthenticated
	}
	for _, v := range []string{q.ID, q.Kind, q.Query, q.TermID, q.TargetID} {
		if !validText(v, 500, true) {
			return out, qw, ErrInput
		}
	}
	if len(q.After) > 2048 {
		return out, qw, ErrInput
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	h := hash(token)
	_, located, e := s.Repo.LocateToken(ctx, h)
	if e != nil {
		return out, qw, lookupError(e)
	}
	var grant GrantRecord
	e = s.transaction(ctx, located.Owner, located.View.AppID, func(t Transaction) error {
		var e error
		grant, qw, e = s.authorizeToken(t, h, scope, true)
		return e
	})
	if e != nil {
		return out, qw, e
	}
	if s.Source == nil {
		return out, qw, ErrUnavailable
	}
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	value, e := s.Source.Read(readCtx, grant.Owner, scope, q)
	if e != nil {
		return out, qw, e
	}
	if e = readCtx.Err(); e != nil {
		return out, qw, ErrUnavailable
	}
	value, e = project(scope, value)
	if e != nil {
		return out, qw, e
	}
	// Recheck after provider I/O. A concurrent withdrawal must discard already-fetched data.
	e = s.transaction(ctx, located.Owner, located.View.AppID, func(t Transaction) error {
		current, _, e := s.authorizeToken(t, h, scope, false)
		if e != nil {
			return e
		}
		value.Subject = current.View.Subject
		if value.Profile != nil {
			profile := *value.Profile
			profile.ID = current.View.Subject
			value.Profile = &profile
		}
		value.Scope = scope
		return t.Event(grant.Owner, "data_returned", grant.View.ID, scope)
	})
	if e != nil {
		return out, qw, e
	}
	return value, qw, nil
}
func project(scope string, v Data) (Data, error) {
	out := Data{Scope: scope, Next: v.Next}
	if len(v.Next) > 4096 {
		return out, ErrUnavailable
	}
	switch scope {
	case "student_status":
		if v.StudentStatus == nil || v.StudentStatus.EvaluatedAt.IsZero() {
			return out, ErrUnavailable
		}
		out.StudentStatus = v.StudentStatus
	case "schools":
		if v.Schools == nil || len(*v.Schools) > 100 {
			return out, ErrUnavailable
		}
		out.Schools = v.Schools
	case "qq_binding_status", "qq_binding_details":
		if v.QQBinding == nil {
			return out, ErrUnavailable
		}
		b := *v.QQBinding
		if scope == "qq_binding_status" {
			out.QQBinding = &QQBinding{Bound: b.Bound}
			break
		}
		if b.Bound {
			if len(b.Number) < 5 || len(b.Number) > 20 || b.Number[0] == '0' {
				return out, ErrUnavailable
			}
			for _, c := range b.Number {
				if c < '0' || c > '9' {
					return out, ErrUnavailable
				}
			}
		} else if b.Number != "" {
			return out, ErrUnavailable
		}
		out.QQBinding = &b
	case "profile":
		if v.Profile == nil || !validText(v.Profile.Nickname, 20, true) || !validText(v.Profile.Bio, 120, true) {
			return out, ErrUnavailable
		}
		out.Profile = v.Profile
	case "schedule":
		if v.Schedule == nil || len(*v.Schedule) > 100 {
			return out, ErrUnavailable
		}
		out.Schedule = v.Schedule
	case "catalog":
		if v.Catalog == nil || len(*v.Catalog) > 100 {
			return out, ErrUnavailable
		}
		out.Catalog = v.Catalog
	case "public_reviews":
		if v.Reviews == nil || len(*v.Reviews) > 100 {
			return out, ErrUnavailable
		}
		out.Reviews = v.Reviews
	default:
		return out, ErrInput
	}
	b, e := json.Marshal(out)
	if e != nil || len(b) > 2*1024*1024 {
		return Data{}, ErrUnavailable
	}
	return out, nil
}
