package postgres

import (
	"context"
	"database/sql"
	op "github.com/StuHelper/stuhelper-open-platform"
	"time"
)

func (t *transaction) RevokeCodeTokens(consent, grant string) error {
	// Historical tokens lacking a code binding are revoked conservatively by grant.
	_, err := t.tx.ExecContext(t.ctx, `DELETE FROM open_platform.tokens WHERE document->>'ConsentID'=$1 OR (grant_id=$2 AND COALESCE(document->>'ConsentID','')='')`, consent, grant)
	return safe(err)
}

func (r *Repository) Cleanup(ctx context.Context, now time.Time, limit int) (int, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, safe(err)
	}
	defer tx.Rollback()
	total := 0
	for _, query := range []struct {
		sql    string
		cutoff time.Time
	}{
		{`DELETE FROM open_platform.requests WHERE (actor,key) IN (SELECT actor,key FROM open_platform.requests WHERE created_at <= $1 ORDER BY created_at,actor,key LIMIT $2)`, now.Add(-24 * time.Hour)},
		{`DELETE FROM open_platform.tokens WHERE hash IN (SELECT hash FROM open_platform.tokens WHERE expires_at <= $1 ORDER BY expires_at,hash LIMIT $2)`, now},
		{`DELETE FROM open_platform.consents WHERE id IN (SELECT id FROM open_platform.consents WHERE expires_at <= $1 ORDER BY expires_at,id LIMIT $2)`, now.Add(-24 * time.Hour)},
		{`DELETE FROM open_platform.events WHERE id IN (SELECT id FROM open_platform.events WHERE created_at <= $1 ORDER BY created_at,id LIMIT $2)`, now.AddDate(-1, 0, 0)},
		{`DELETE FROM open_platform.notices WHERE id IN (SELECT id FROM open_platform.notices WHERE created_at <= $1 ORDER BY created_at,id LIMIT $2)`, now.AddDate(-1, 0, 0)},
		{`DELETE FROM open_platform.quotas WHERE (app_id,day) IN (SELECT app_id,day FROM open_platform.quotas WHERE day < to_char($1::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD') ORDER BY day,app_id LIMIT $2)`, now.Add(-24 * time.Hour)},
	} {
		result, e := tx.ExecContext(ctx, query.sql, query.cutoff, limit)
		if e != nil {
			return 0, safe(e)
		}
		n, e := result.RowsAffected()
		if e != nil {
			return 0, safe(e)
		}
		total += int(n)
	}
	if err = tx.Commit(); err != nil {
		return 0, safe(err)
	}
	return total, nil
}

func buildCategoryBacklog(now time.Time, oldest sql.NullTime, extraPending bool) op.CategoryBacklog {
	if !oldest.Valid {
		return op.CategoryBacklog{HasBacklog: extraPending}
	}
	due := oldest.Time.UTC()
	lag := int64(now.Sub(due) / time.Second)
	if lag < 0 {
		lag = 0
	}
	return op.CategoryBacklog{HasBacklog: true, OldestExpiredAt: &due, LagSeconds: lag}
}

func (r *Repository) Backlog(ctx context.Context, now time.Time) (op.BacklogSummary, error) {
	now = now.UTC()
	out := op.BacklogSummary{ObservedAt: now}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, safe(err)
	}
	defer tx.Rollback()

	var grantDue, reqDue, tokDue, conDue, evtDue, notDue, quoDue sql.NullTime
	var nonExpiryPending bool
	err = tx.QueryRowContext(ctx, `
SELECT
	(SELECT expires_at FROM open_platform.grants WHERE state='active' AND expires_at <= $1 ORDER BY expires_at,id LIMIT 1),
	(
		EXISTS (SELECT 1 FROM open_platform.grants g JOIN open_platform.apps a ON a.id=g.app_id WHERE g.state='active' AND (a.state<>'active' OR g.app_revision<>a.revision))
		OR EXISTS (SELECT 1 FROM open_platform.owners u JOIN open_platform.grants g ON g.owner_key=u.owner_key WHERE u.closed AND g.state='active')
		OR EXISTS (SELECT 1 FROM open_platform.owners d JOIN open_platform.apps a ON a.owner_key=d.owner_key JOIN open_platform.grants g ON g.app_id=a.id WHERE d.closed AND g.state='active')
	),
	(SELECT created_at + interval '24 hours' FROM open_platform.requests WHERE created_at <= $2 ORDER BY created_at,actor,key LIMIT 1),
	(SELECT expires_at FROM open_platform.tokens WHERE expires_at <= $1 ORDER BY expires_at,hash LIMIT 1),
	(SELECT expires_at + interval '24 hours' FROM open_platform.consents WHERE expires_at <= $2 ORDER BY expires_at,id LIMIT 1),
	(SELECT created_at + interval '1 year' FROM open_platform.events WHERE created_at <= $3 ORDER BY created_at,id LIMIT 1),
	(SELECT created_at + interval '1 year' FROM open_platform.notices WHERE created_at <= $3 ORDER BY created_at,id LIMIT 1),
	(SELECT ((day::date + 2)::timestamp AT TIME ZONE 'UTC') FROM open_platform.quotas WHERE day < to_char($2::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD') ORDER BY day,app_id LIMIT 1)`,
		now, now.Add(-24*time.Hour), now.AddDate(-1, 0, 0),
	).Scan(&grantDue, &nonExpiryPending, &reqDue, &tokDue, &conDue, &evtDue, &notDue, &quoDue)
	if err != nil {
		return out, safe(err)
	}
	if err = tx.Commit(); err != nil {
		return out, safe(err)
	}

	out.PendingNotices = buildCategoryBacklog(now, grantDue, nonExpiryPending)
	out.ExpiredRequests = buildCategoryBacklog(now, reqDue, false)
	out.ExpiredTokens = buildCategoryBacklog(now, tokDue, false)
	out.ExpiredConsents = buildCategoryBacklog(now, conDue, false)
	out.ExpiredEvents = buildCategoryBacklog(now, evtDue, false)
	out.ExpiredNotices = buildCategoryBacklog(now, notDue, false)
	out.ExpiredQuotas = buildCategoryBacklog(now, quoDue, false)

	for _, c := range []op.CategoryBacklog{
		out.PendingNotices,
		out.ExpiredRequests,
		out.ExpiredTokens,
		out.ExpiredConsents,
		out.ExpiredEvents,
		out.ExpiredNotices,
		out.ExpiredQuotas,
	} {
		if c.HasBacklog {
			out.HasBacklog = true
		}
		if c.LagSeconds > out.MaxLagSeconds {
			out.MaxLagSeconds = c.LagSeconds
		}
		if c.OldestExpiredAt != nil && (out.OldestExpiredAt == nil || c.OldestExpiredAt.Before(*out.OldestExpiredAt)) {
			ts := *c.OldestExpiredAt
			out.OldestExpiredAt = &ts
		}
	}
	return out, nil
}
