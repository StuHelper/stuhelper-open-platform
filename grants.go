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
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
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
	e = s.sharedTransaction(ctx, p.Owner, "", func(t Transaction) error {
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
				g.View.Scopes = []string{}
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
	if !validID(id) || in.Revision < 1 || (in.RevokeAll && len(in.Scopes) > 0) {
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
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	located, e := s.Repo.LocateGrant(dbCtx, id)
	if e != nil {
		return out, e
	}
	if located.Owner != p.Owner {
		return out, ErrNotFound
	}
	e = s.sharedTransaction(dbCtx, p.Owner, located.View.AppID, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		var e error
		out, e = replay(t, p.Owner, key, "revoke:"+id, in, s.now(), func() (Grant, auditSpec, error) {
			g, e := t.Grant(id)
			if e != nil {
				return out, auditSpec{}, e
			}
			if g.View.State != "active" {
				return out, auditSpec{}, WithReason(ErrConflict, "state_conflict")
			}
			if g.View.Revision != in.Revision || (!wholeGrant && !subset(in.Scopes, g.View.Scopes)) {
				return out, auditSpec{}, WithReason(ErrConflict, "revision_mismatch")
			}
			a, e := t.App(g.View.AppID)
			if e != nil {
				return out, auditSpec{}, e
			}
			reason, e := s.grantReason(t, g, a)
			if e != nil {
				return out, auditSpec{}, e
			}
			now := s.now()
			g.UpdatedAt = now
			targetScopes := in.Scopes
			if wholeGrant {
				targetScopes = g.View.Scopes
			}
			terminationReason := "user_revoked"
			if reason != "" {
				terminationReason = reason
				if e = s.notice(t, g, g.View.Scopes, reason); e != nil {
					return out, auditSpec{}, e
				}
				g.View.Scopes = []string{}
				g.View.State = "revoked"
				g.View.TerminationReason = terminationReason
				g.TerminatedAt = &now
			} else {
				if e = s.notice(t, g, targetScopes, "user_revoked"); e != nil {
					return out, auditSpec{}, e
				}
				g.View.Scopes = difference(g.View.Scopes, targetScopes)
				if len(g.View.Scopes) == 0 {
					g.View.State = "revoked"
					g.View.TerminationReason = terminationReason
					g.TerminatedAt = &now
				}
			}
			g.View.UpdatedAt = s.now().Truncate(time.Microsecond)
			g.View.Revision++
			if e = t.SaveGrant(g); e != nil {
				return out, auditSpec{}, e
			}
			return g.View, auditSpec{actor: p.Owner, action: "grant_revoked", target: id, reason: terminationReason}, nil
		})
		return e
	})
	return out, e
}

// CloseAccount installs a permanent grant-owner fence and application epochs in the same transaction.
// It is a trusted module port; there is no HTTP route that accepts another account key.
func (s *Service) CloseAccount(ctx context.Context, owner, closureID string) error {
	if !validOwner(owner) || !validLine(closureID, 128, false) {
		return ErrInput
	}
	return s.transaction(ctx, owner, "", func(t Transaction) error {
		_, e := replay(t, owner, "closure:"+hash(closureID), "close-account", closureID, s.now(), func() (bool, auditSpec, error) {
			if e := t.CloseOwner(owner, closureID); e != nil {
				return false, auditSpec{}, e
			}
			if e := t.SuspendOwnedApps(owner, s.now().Truncate(time.Microsecond)); e != nil {
				return false, auditSpec{}, e
			}
			return true, auditSpec{actor: owner, action: "account_closed", target: owner}, nil
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
		e = s.sharedTransaction(ctx, row.Owner, row.View.AppID, func(t Transaction) error {
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
			now := s.now()
			g.View.Scopes = []string{}
			g.View.State = "revoked"
			g.View.TerminationReason = reason
			g.View.UpdatedAt = s.now().Truncate(time.Microsecond)
			g.View.Revision++
			g.UpdatedAt = now
			g.TerminatedAt = &now
			if e = t.SaveGrant(g); e != nil {
				return e
			}
			return t.Event(g.Owner, "grant_terminated", g.View.ID, g.View.AppID, reason, s.now())
		})
		if e != nil {
			return done, e
		}
		done++
	}
	return done, nil
}
func (s *Service) preAuthenticateApp(ctx context.Context, app, secret string) error {
	if secret == "" {
		return nil
	}
	if e := s.ready(); e != nil {
		return e
	}
	a, e := s.Repo.LocateApp(ctx, app)
	if e != nil {
		return lookupError(e)
	}
	if !sameHash(a.SecretHash, hash(secret)) {
		return ErrUnauthenticated
	}
	return nil
}
func (s *Service) Notices(ctx context.Context, p Principal, app, secret, after string, limit int) (Page[Notice], error) {
	return s.ListNotices(ctx, p, app, secret, false, after, limit)
}
func (s *Service) ListNotices(ctx context.Context, p Principal, app, secret string, pendingAck bool, after string, limit int) (Page[Notice], error) {
	var out Page[Notice]
	if !validID(app) {
		return out, ErrInput
	}
	if secret != "" && !validToken(secret, 256) {
		return out, ErrUnauthenticated
	}
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
	if e := s.preAuthenticateApp(ctx, app, secret); e != nil {
		return out, e
	}
	e = s.sharedTransaction(ctx, p.Owner, app, func(t Transaction) error {
		if _, e := authenticatedApp(t, p, app, secret); e != nil {
			return e
		}
		rows, e := t.Notices(app, pendingAck, after, limit+1)
		if e != nil {
			return e
		}
		out = page(rows, limit, func(n Notice) string { return stringRevision(n.Sequence) })
		now := s.now()
		unseen := []string{}
		for i, n := range out.Items {
			if n.SeenAt == nil {
				n.SeenAt = &now
				out.Items[i] = n
				unseen = append(unseen, n.ID)
			}
		}
		return t.MarkNoticesSeen(unseen, now)
	})
	return out, e
}
func parseOverdueCursor(after string) (OverdueCursor, error) {
	if after == "" {
		return OverdueCursor{}, nil
	}
	rawMicros, appID, ok := strings.Cut(after, "|")
	if !ok || appID == "" || !utf8.ValidString(appID) || strings.ContainsFunc(appID, unicode.IsControl) {
		return OverdueCursor{}, ErrInput
	}
	micros, e := strconv.ParseInt(rawMicros, 10, 64)
	if e != nil {
		return OverdueCursor{}, ErrInput
	}
	return OverdueCursor{Set: true, OldestNoticeAt: time.UnixMicro(micros).UTC(), AppID: appID}, nil
}
func formatOverdueCursor(v OverdueNoticeApplication) string {
	return strconv.FormatInt(v.OldestNoticeAt.UTC().UnixMicro(), 10) + "|" + v.AppID
}
func (s *Service) OverdueNoticeApplications(ctx context.Context, p Principal, olderThanDays int, after string, limit int) (Page[OverdueNoticeApplication], error) {
	var out Page[OverdueNoticeApplication]
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	if !p.Admin {
		return out, ErrForbidden
	}
	if olderThanDays == 0 {
		olderThanDays = 7
	}
	if olderThanDays < 1 || olderThanDays > 365 {
		return out, ErrInput
	}
	limit, e := pagination(after, limit)
	if e != nil {
		return out, e
	}
	cursor, e := parseOverdueCursor(after)
	if e != nil {
		return out, e
	}
	cutoff := s.now().Add(-time.Duration(olderThanDays) * 24 * time.Hour)
	e = s.transaction(ctx, p.Owner, "", func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		rows, e := t.OverdueNoticeApps(cutoff, cursor, limit+1)
		if e != nil {
			return e
		}
		out = page(rows, limit, formatOverdueCursor)
		return nil
	})
	return out, e
}
func ackRank(status string) int {
	switch status {
	case "received":
		return 1
	case "retention_exception":
		return 2
	case "deleted":
		return 3
	default:
		return 0
	}
}

func (s *Service) Acknowledge(ctx context.Context, p Principal, app, secret, id, key string, in Acknowledgement) (Notice, error) {
	var out Notice
	if !validID(app) || !validID(id) || !slices.Contains([]string{"received", "deleted", "retention_exception"}, in.Status) || !validText(in.Note, 1000, in.Status != "retention_exception") {
		return out, ErrInput
	}
	if secret != "" && !validToken(secret, 256) {
		return out, ErrUnauthenticated
	}
	if e := s.preAuthenticateApp(ctx, app, secret); e != nil {
		return out, e
	}
	e := s.sharedTransaction(ctx, p.Owner, app, func(t Transaction) error {
		if e := t.LockAppAck(app); e != nil {
			return e
		}
		if _, e := authenticatedApp(t, p, app, secret); e != nil {
			return e
		}
		auditActor := "app:" + app
		if secret == "" {
			auditActor = p.Owner
		}
		var e error
		out, e = replay(t, "app:"+app, key, "notice-ack:"+id, in, s.now(), func() (Notice, auditSpec, error) {
			n, e := t.Notice(id)
			if e != nil {
				return out, auditSpec{}, e
			}
			if n.AppID != app {
				return out, auditSpec{}, ErrNotFound
			}
			if ackRank(in.Status) < ackRank(n.Acknowledgement) {
				return out, auditSpec{}, WithReason(ErrConflict, "state_conflict")
			}
			n.Acknowledgement = in.Status
			n.Note = in.Note
			now := s.now()
			n.AcknowledgedAt = &now
			if n.SeenAt == nil {
				n.SeenAt = &now
			}
			if e = t.SaveNotice(n); e != nil {
				return out, auditSpec{}, e
			}
			return n, auditSpec{actor: auditActor, action: "notice_acknowledged", target: n.ID, reason: in.Note}, nil
		})
		return e
	})
	return out, e
}
