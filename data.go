package openplatform

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func validSingle(v string, max int, empty bool) bool {
	return utf8.ValidString(v) && (empty || strings.TrimSpace(v) != "") && utf8.RuneCountInString(v) <= max && !strings.ContainsFunc(v, unicode.IsControl)
}

func stringRevision(v int64) string { return strconv.FormatInt(v, 10) }
func (s *Service) authorizeToken(t Transaction, h, scope string, count bool) (GrantRecord, error) {
	var empty GrantRecord
	v, e := t.Token(h)
	if e != nil {
		return empty, lookupError(e)
	}
	g, e := t.Grant(v.GrantID)
	if e != nil {
		return empty, lookupError(e)
	}
	a, e := t.App(g.View.AppID)
	if e != nil {
		return empty, e
	}
	reason, e := s.grantReason(t, g, a)
	if e != nil {
		return empty, e
	}
	if reason != "" || !s.now().Before(v.ExpiresAt) || v.GrantRevision != g.View.Revision || v.AppRevision != a.View.Revision {
		return empty, ErrUnauthenticated
	}
	if !slices.Contains(g.View.Scopes, scope) || !slices.Contains(a.View.ApprovedScopes, scope) {
		return empty, ErrForbidden
	}
	if count {
		if e = t.Quota(a.View.ID, s.now().Format("2006-01-02"), a.View.Policy.DailyQuota); e != nil {
			return empty, e
		}
		if e = t.Event(g.Owner, "data_requested", g.View.ID, scope, "", s.now()); e != nil {
			return empty, e
		}
	}
	return g, nil
}
func (s *Service) Read(ctx context.Context, token, scope string, q Query) (Data, error) {
	var out Data
	if e := s.ready(); e != nil {
		return out, e
	}
	if !slices.Contains(Scopes, scope) || q.Limit < 0 || q.Limit > 100 {
		return out, ErrInput
	}
	if !strings.HasPrefix(token, "op_") || !validToken(token, 100) {
		return out, ErrUnauthenticated
	}
	for _, v := range []string{q.ID, q.Kind, q.Query, q.TermID, q.TargetID} {
		if !validLine(v, 500, true) {
			return out, ErrInput
		}
	}
	if q.After != "" && !validToken(q.After, 2048) {
		return out, ErrInput
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if s.Source == nil {
		return out, ErrUnavailable
	}
	h := hash(token)
	preCtx, preCancel := context.WithTimeout(ctx, 5*time.Second)
	defer preCancel()
	_, located, e := s.Repo.LocateToken(preCtx, h)
	if e != nil {
		return out, lookupError(e)
	}
	var grant GrantRecord
	e = s.sharedTransaction(preCtx, located.Owner, located.View.AppID, func(t Transaction) error { var e error; grant, e = s.authorizeToken(t, h, scope, true); return e })
	if e != nil {
		return out, e
	}
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	value, e := s.Source.Read(readCtx, grant.Owner, scope, q)
	if e != nil {
		switch {
		case errors.Is(e, ErrForbidden):
			return out, ErrForbidden
		case errors.Is(e, ErrNotFound):
			return out, ErrNotFound
		case errors.Is(e, ErrInput):
			return out, ErrInput
		default:
			return out, ErrUnavailable
		}
	}
	if e = readCtx.Err(); e != nil {
		return out, ErrUnavailable
	}
	value, e = project(scope, value)
	if e != nil {
		return out, e
	}
	// Recheck after provider I/O. A concurrent withdrawal must discard already-fetched data.
	e = s.sharedTransaction(ctx, located.Owner, located.View.AppID, func(t Transaction) error {
		current, e := s.authorizeToken(t, h, scope, false)
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
		if e = t.TouchGrantRead(grant.View.ID, s.now().Truncate(time.Microsecond)); e != nil {
			return e
		}
		return t.Event(grant.Owner, "data_returned", grant.View.ID, scope, "", s.now())
	})
	if e != nil {
		return out, e
	}
	return value, nil
}
func project(scope string, v Data) (Data, error) {
	out := Data{Scope: scope, Next: v.Next}
	if len(v.Next) > 4096 || !validSingle(v.Next, 4096, true) {
		return out, ErrUnavailable
	}
	switch scope {
	case "student_status":
		if v.StudentStatus == nil || v.StudentStatus.EvaluatedAt.IsZero() {
			return out, ErrUnavailable
		}
		st := *v.StudentStatus
		out.StudentStatus = &st
	case "schools":
		if v.Schools == nil || len(*v.Schools) > 100 {
			return out, ErrUnavailable
		}
		schools := make([]School, 0, len(*v.Schools))
		for _, item := range *v.Schools {
			if !validSingle(item.ID, 128, false) || !validSingle(item.Name, 200, false) {
				return out, ErrUnavailable
			}
			schools = append(schools, item)
		}
		out.Schools = &schools
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
		if v.Profile == nil || !validLine(v.Profile.Nickname, 20, true) || !validText(v.Profile.Bio, 120, true) {
			return out, ErrUnavailable
		}
		p := *v.Profile
		out.Profile = &p
	case "schedule":
		if v.Schedule == nil || len(*v.Schedule) > 100 {
			return out, ErrUnavailable
		}
		schedule := make([]ScheduleItem, 0, len(*v.Schedule))
		for _, item := range *v.Schedule {
			if !item.Active {
				continue
			}
			if !validSingle(item.ID, 128, false) || !validSingle(item.CourseID, 128, false) || !validSingle(item.CourseName, 500, true) || !validSingle(item.TermID, 128, false) || !validSingle(item.ClassID, 128, false) || item.FetchedAt.IsZero() || len(item.Meetings) > 100 {
				return out, ErrUnavailable
			}
			meetings := make([]ScheduleMeeting, 0, len(item.Meetings))
			for _, m := range item.Meetings {
				if !validSingle(m.ID, 128, false) || !validText(m.TimeText, 2000, true) || !validSingle(m.Location, 512, true) {
					return out, ErrUnavailable
				}
				meetings = append(meetings, m)
			}
			item.Meetings = meetings
			schedule = append(schedule, item)
		}
		out.Schedule = &schedule
	case "catalog":
		if v.Catalog == nil || len(*v.Catalog) > 100 {
			return out, ErrUnavailable
		}
		catalog := make([]CatalogItem, 0, len(*v.Catalog))
		for _, item := range *v.Catalog {
			if !validSingle(item.ID, 128, false) || !validSingle(item.Kind, 40, false) || !validSingle(item.SchoolID, 128, false) || !validSingle(item.Name, 500, false) || !validSingle(item.CourseID, 128, true) || !validSingle(item.TermID, 128, true) || !validSingle(item.DepartmentID, 128, true) || !validText(item.Biography, 10000, true) || item.Revision < 0 {
				return out, ErrUnavailable
			}
			catalog = append(catalog, item)
		}
		out.Catalog = &catalog
	case "public_reviews":
		if v.Reviews == nil || len(*v.Reviews) > 100 {
			return out, ErrUnavailable
		}
		reviews := make([]ReviewItem, 0, len(*v.Reviews))
		for _, item := range *v.Reviews {
			if !validSingle(item.ID, 128, false) || !validSingle(item.Kind, 40, false) || !validSingle(item.TargetID, 128, false) || !validText(item.Body, 100000, false) || item.CreatedAt.IsZero() {
				return out, ErrUnavailable
			}
			for _, score := range item.Ratings {
				if score < 0 || score > 10 {
					return out, ErrUnavailable
				}
			}
			reviews = append(reviews, item)
		}
		out.Reviews = &reviews
	default:
		return out, ErrInput
	}
	b, e := json.Marshal(out)
	if e != nil || len(b) > 2*1024*1024 {
		return Data{}, ErrUnavailable
	}
	return out, nil
}
