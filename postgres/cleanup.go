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
		{`DELETE FROM open_platform.grants WHERE id IN (SELECT g.id FROM open_platform.grants g JOIN open_platform.apps a ON a.id=g.app_id WHERE a.archived_at IS NOT NULL AND a.archived_at <= $1 AND NOT EXISTS (SELECT 1 FROM open_platform.tokens t WHERE t.grant_id=g.id) ORDER BY a.archived_at,g.id LIMIT $2)`, now.AddDate(-1, 0, 0)},
		{`DELETE FROM open_platform.apps WHERE id IN (SELECT a.id FROM open_platform.apps a WHERE a.archived_at IS NOT NULL AND a.archived_at <= $1 AND NOT EXISTS (SELECT 1 FROM open_platform.grants g WHERE g.app_id=a.id) AND NOT EXISTS (SELECT 1 FROM open_platform.consents c WHERE c.app_id=a.id) AND NOT EXISTS (SELECT 1 FROM open_platform.notices n WHERE n.app_id=a.id) AND NOT EXISTS (SELECT 1 FROM open_platform.quotas q WHERE q.app_id=a.id) ORDER BY a.archived_at,a.id LIMIT $2)`, now.AddDate(-1, 0, 0)},
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

func buildCategoryBacklog(now time.Time, oldest sql.NullTime) op.CategoryBacklog {
	if !oldest.Valid {
		return op.CategoryBacklog{}
	}
	due := oldest.Time.UTC()
	lag := int64(now.Sub(due) / time.Second)
	if lag < 0 {
		lag = 0
	}
	return op.CategoryBacklog{HasBacklog: true, OldestExpiredAt: &due, LagSeconds: lag}
}

// Go's yearly cutoff normalizes an invalid February 29 to March 1.
func annualRetentionDue(created sql.NullTime) sql.NullTime {
	if !created.Valid {
		return created
	}
	t := created.Time.UTC()
	due := t.AddDate(1, 0, 0)
	if t.Month() == time.February && t.Day() == 29 {
		due = time.Date(due.Year(), time.March, 1, 0, 0, 0, 0, time.UTC)
	} else if t.Month() == time.March && t.Day() == 1 && due.AddDate(0, 0, -1).Day() == 29 {
		due = due.AddDate(0, 0, -1)
	}
	return sql.NullTime{Time: due, Valid: true}
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
	var archivedGrants, archivedApps sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT
    LEAST(
        (SELECT expires_at FROM open_platform.grants WHERE state='active' AND expires_at <= $1 ORDER BY expires_at,id LIMIT 1),
        (SELECT invalidated_at FROM open_platform.invalid_revisions i
         WHERE EXISTS (SELECT 1 FROM open_platform.grants g WHERE g.state='active' AND g.app_id=i.app_id AND g.app_revision=i.revision)
         ORDER BY invalidated_at,app_id,revision LIMIT 1),
        (SELECT closed_at FROM open_platform.owners u WHERE u.closed AND EXISTS (
          SELECT 1 FROM open_platform.grants g WHERE g.owner_key=u.owner_key AND g.state='active')
         ORDER BY closed_at,owner_key LIMIT 1)
    ),
	(SELECT created_at + interval '24 hours' FROM open_platform.requests WHERE created_at <= $2 ORDER BY created_at,actor,key LIMIT 1),
	(SELECT expires_at FROM open_platform.tokens WHERE expires_at <= $1 ORDER BY expires_at,hash LIMIT 1),
	(SELECT expires_at + interval '24 hours' FROM open_platform.consents WHERE expires_at <= $2 ORDER BY expires_at,id LIMIT 1),
	(SELECT created_at FROM open_platform.events WHERE created_at <= $3 ORDER BY created_at,id LIMIT 1),
	(SELECT created_at FROM open_platform.notices WHERE created_at <= $3 ORDER BY created_at,id LIMIT 1),
	(SELECT ((day::date + 2)::timestamp AT TIME ZONE 'UTC') FROM open_platform.quotas WHERE day < to_char($2::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD') ORDER BY day,app_id LIMIT 1),
    (SELECT archived_at FROM open_platform.apps a WHERE archived_at<=$3 AND EXISTS (SELECT 1 FROM open_platform.grants g WHERE g.app_id=a.id AND NOT EXISTS (SELECT 1 FROM open_platform.tokens t WHERE t.grant_id=g.id)) ORDER BY archived_at,id LIMIT 1),
    (SELECT archived_at FROM open_platform.apps a WHERE archived_at<=$3 AND NOT EXISTS (SELECT 1 FROM open_platform.grants g WHERE g.app_id=a.id) AND NOT EXISTS (SELECT 1 FROM open_platform.consents c WHERE c.app_id=a.id) AND NOT EXISTS (SELECT 1 FROM open_platform.notices n WHERE n.app_id=a.id) AND NOT EXISTS (SELECT 1 FROM open_platform.quotas q WHERE q.app_id=a.id) ORDER BY archived_at,id LIMIT 1)`,
		now, now.Add(-24*time.Hour), now.AddDate(-1, 0, 0),
	).Scan(&grantDue, &reqDue, &tokDue, &conDue, &evtDue, &notDue, &quoDue, &archivedGrants, &archivedApps)
	if err != nil {
		return out, safe(err)
	}
	if err = tx.Commit(); err != nil {
		return out, safe(err)
	}

	out.PendingNotices = buildCategoryBacklog(now, grantDue)
	out.ExpiredRequests = buildCategoryBacklog(now, reqDue)
	out.ExpiredTokens = buildCategoryBacklog(now, tokDue)
	out.ExpiredConsents = buildCategoryBacklog(now, conDue)
	out.ExpiredEvents = buildCategoryBacklog(now, annualRetentionDue(evtDue))
	out.ExpiredNotices = buildCategoryBacklog(now, annualRetentionDue(notDue))
	out.ExpiredQuotas = buildCategoryBacklog(now, quoDue)

	out.ArchivedGrants = buildCategoryBacklog(now, annualRetentionDue(archivedGrants))
	out.ArchivedApps = buildCategoryBacklog(now, annualRetentionDue(archivedApps))
	for _, c := range []op.CategoryBacklog{out.ArchivedGrants, out.ArchivedApps,
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
