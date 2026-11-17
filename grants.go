package openplatform

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func grantEffectiveReason(ownerClosed bool, g GrantRecord, appState string, currentAppRevision int64, now time.Time) string {
	if ownerClosed {
		return "account_closed"
	}
	if g.View.State != "active" {
		if g.View.TerminationReason != "" {
			return g.View.TerminationReason
		}
		return "user_revoked"
	}
	if !now.Before(g.View.ExpiresAt) {
		return "expired"
	}
	if appState != "active" || currentAppRevision != g.AppRevision {
		return "application_changed"
	}
	return ""
}
func (s *Service) grantReason(t Transaction, g GrantRecord, a AppRecord) (string, error) {
	for _, owner := range []string{g.Owner, a.Owner} {
		closed, e := t.Closed(owner)
		if e != nil {
			return "", e
		}
		if closed {
			return "account_closed", nil
		}
	}
	return grantEffectiveReason(false, g, a.View.State, a.View.Revision, s.now()), nil
}
func (s *Service) notice(t Transaction, g GrantRecord, scopes []string, reason string) error {
	id := hash(g.View.ID + ":" + stringRevision(g.View.Revision) + ":" + reason + ":" + strings.Join(scopes, ","))
	_, e := t.Notice(id)
	if e == nil {
		return nil
	}
	if !errors.Is(e, ErrNotFound) {
		return e
	}
	return t.SaveNotice(Notice{ID: id, AppID: g.View.AppID, Subject: g.View.Subject, Scopes: scopes, Reason: reason, CreatedAt: s.now()})
}
func parseGrantCursor(after string) (GrantCursor, error) {
	if after == "" {
		return GrantCursor{}, nil
	}
	parts := strings.SplitN(after, "|", 3)
	if len(parts) != 3 || (parts[0] != "0" && parts[0] != "1") || parts[2] == "" || !utf8.ValidString(parts[2]) || strings.ContainsFunc(parts[2], unicode.IsControl) {
		return GrantCursor{}, ErrInput
	}
	micros, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil {
		return GrantCursor{}, ErrInput
	}
	rank := 0
	if parts[0] == "1" {
		rank = 1
	}
	return GrantCursor{Set: true, Rank: rank, UpdatedAt: time.UnixMicro(micros).UTC(), ID: parts[2]}, nil
}
func formatGrantCursor(g Grant) string {
	rank := "0"
	if g.State != "active" {
		rank = "1"
	}
	return rank + "|" + strconv.FormatInt(g.UpdatedAt.UTC().UnixMicro(), 10) + "|" + g.ID
}
func (s *Service) Grants(ctx context.Context, p Principal, after string, limit int) (Page[Grant], error) {
	return s.ListGrants(ctx, p, "", after, limit)
}
func (s *Service) ListGrants(ctx context.Context, p Principal, state, after string, limit int) (Page[Grant], error) {
	var out Page[Grant]
	if state != "" && state != "active" && state != "revoked" {
		return out, ErrInput
	}
	limit, e := pagination(after, limit)
	if e != nil {
		return out, e
	}
	cursor, e := parseGrantCursor(after)
	if e != nil {
		return out, e
	}
	e = s.transaction(ctx, p.Owner, "", func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		now := s.now()
		rows, e := t.ListGrants(p.Owner, state, now, cursor, limit+1)
		if e != nil {
			return e
		}
		items := []Grant{}
		for _, entry := range rows {
			g := entry.Record
			if g.View.Scopes == nil {
				g.View.Scopes = []string{}
			}
			reason := grantEffectiveReason(entry.OwnerClosed, g, entry.AppState, entry.CurrentAppRevision, now)
			if reason != "" {
				g.View.State = "revoked"
				g.View.TerminationReason = reason
			} else {
				g.View.State = "active"
				g.View.TerminationReason = ""
			}
			items = append(items, g.View)
		}
		out = page(items, limit, formatGrantCursor)
		return nil
	})
	return out, e
}
func (s *Service) Revoke(ctx context.Context, p Principal, id, key string, in RevokeInput) (Grant, error) {
	var out Grant
	if e := s.ready(); e != nil {
		return out, e
	}
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	if in.Revision < 1 || (in.RevokeAll && len(in.Scopes) > 0) {
		return out, ErrInput
	}
	wholeGrant := in.RevokeAll || in.Scopes == nil
	if wholeGrant {
		in.RevokeAll = true
		in.Scopes = nil
	} else {
		var e error
		in.Scopes, e = validateScopes(in.Scopes, false)
		if e != nil {
			return out, ErrInput
		}
	}
	located, e := s.Repo.LocateGrant(ctx, id)
	if e != nil {
		return out, e
	}
	if located.Owner != p.Owner {
		return out, ErrNotFound
	}
	e = s.transaction(ctx, p.Owner, located.View.AppID, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		var e error
		out, e = replay(t, p.Owner, key, "revoke:"+id, in, func() (Grant, error) {
			g, e := t.Grant(id)
			if e != nil {
				return out, e
			}
			a, e := t.App(g.View.AppID)
			if e != nil {
				return out, e
			}
			reason, e := s.grantReason(t, g, a)
			if e != nil {
				return out, e
			}
			if g.View.State != "active" || reason != "" || g.View.Revision != in.Revision {
				return out, ErrConflict
			}
			targetScopes := in.Scopes
			if wholeGrant {
				targetScopes = append([]string{}, g.View.Scopes...)
			}
			if len(targetScopes) == 0 || !subset(targetScopes, g.View.Scopes) {
				return out, ErrConflict
			}
			if e = s.notice(t, g, targetScopes, "user_revoked"); e != nil {
				return out, e
			}
			g.View.Scopes = difference(g.View.Scopes, targetScopes)
			if len(g.View.Scopes) == 0 {
				g.View.State = "revoked"
				g.View.TerminationReason = "user_revoked"
			}
			g.View.UpdatedAt = s.now().Truncate(time.Microsecond)
			g.View.Revision++
			if e = t.SaveGrant(g); e != nil {
				return out, e
			}
			return g.View, nil
		})
		return e
	})
	return out, e
}

// CloseAccount installs a permanent grant-owner fence and application epochs in the same transaction.
// It is a trusted module port; there is no HTTP route that accepts another account key.
func (s *Service) CloseAccount(ctx context.Context, owner, closureID string) error {
	if !validOwner(owner) || !validText(closureID, 128, false) {
		return ErrInput
	}
	return s.transaction(ctx, owner, "", func(t Transaction) error {
		_, e := replay(t, owner, "closure:"+closureID, "close-account", closureID, func() (bool, error) {
			if e := t.CloseOwner(owner, closureID); e != nil {
				return false, e
			}
			if e := t.SuspendOwnedApps(owner); e != nil {
				return false, e
			}
			return true, nil
		})
		return e
	})
}

// Work materializes at most limit pending termination notices. Reads already enforce the fence before this worker runs.
func (s *Service) Work(ctx context.Context, limit int) (int, error) {
	if e := s.ready(); e != nil {
		return 0, e
	}
	if limit < 1 || limit > 100 {
		return 0, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, e := s.Repo.WorkCandidates(ctx, s.now(), limit)
	if e != nil {
		return 0, e
	}
	done := 0
	for _, row := range rows {
		e = s.transaction(ctx, row.Owner, row.View.AppID, func(t Transaction) error {
			g, e := t.Grant(row.View.ID)
			if e != nil {
				return e
			}
			if g.View.State != "active" {
				return nil
			}
			a, e := t.App(g.View.AppID)
			if e != nil {
				return e
			}
			reason, e := s.grantReason(t, g, a)
			if e != nil || reason == "" {
				return e
			}
			if e = s.notice(t, g, g.View.Scopes, reason); e != nil {
				return e
			}
			g.View.State = "revoked"
			g.View.TerminationReason = reason
			g.View.UpdatedAt = s.now().Truncate(time.Microsecond)
			g.View.Revision++
			if e = t.SaveGrant(g); e != nil {
				return e
			}
			return t.Event(g.Owner, "grant_terminated", g.View.ID, reason)
		})
		if e != nil {
			return done, e
		}
		done++
	}
	return done, nil
}
func (s *Service) Notices(ctx context.Context, p Principal, app, secret, after string, limit int) (Page[Notice], error) {
	var out Page[Notice]
	if after != "" {
		n, e := strconv.ParseInt(after, 10, 64)
		if e != nil || n < 1 {
			return out, ErrInput
		}
	}
	limit, e := pagination(after, limit)
	if e != nil {
		return out, e
	}
	e = s.transaction(ctx, p.Owner, app, func(t Transaction) error {
		if _, e := authenticatedApp(t, p, app, secret); e != nil {
			return e
		}
		rows, e := t.Notices(app, after, limit+1)
		if e != nil {
			return e
		}
		out = page(rows, limit, func(n Notice) string { return stringRevision(n.Sequence) })
		for i, n := range out.Items {
			if n.SeenAt == nil {
				now := s.now()
				n.SeenAt = &now
				if e = t.SaveNotice(n); e != nil {
					return e
				}
				out.Items[i] = n
			}
		}
		return nil
	})
	return out, e
}
func (s *Service) Acknowledge(ctx context.Context, p Principal, app, secret, id, key string, in Acknowledgement) (Notice, error) {
	var out Notice
	if !slices.Contains([]string{"received", "deleted", "retention_exception"}, in.Status) || !validText(in.Note, 1000, in.Status != "retention_exception") {
		return out, ErrInput
	}
	e := s.transaction(ctx, p.Owner, app, func(t Transaction) error {
		if _, e := authenticatedApp(t, p, app, secret); e != nil {
			return e
		}
		var e error
		out, e = replay(t, "app:"+app, key, "notice-ack:"+id, in, func() (Notice, error) {
			n, e := t.Notice(id)
			if e != nil {
				return out, e
			}
			if n.AppID != app {
				return out, ErrNotFound
			}
			if n.Acknowledgement == "deleted" && in.Status != "deleted" {
				return out, ErrConflict
			}
			n.Acknowledgement = in.Status
			n.Note = in.Note
			now := s.now()
			n.AcknowledgedAt = &now
			if n.SeenAt == nil {
				n.SeenAt = &now
			}
			if e = t.SaveNotice(n); e != nil {
				return out, e
			}
			return n, nil
		})
		return e
	})
	return out, e
}
