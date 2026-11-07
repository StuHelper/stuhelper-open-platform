package postgres

import (
	"context"
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
		{`DELETE FROM open_platform.requests WHERE (actor,key) IN (SELECT actor,key FROM open_platform.requests WHERE created_at <= $1 ORDER BY created_at,actor,key LIMIT $2 FOR UPDATE SKIP LOCKED)`, now.Add(-24 * time.Hour)},
		{`DELETE FROM open_platform.tokens WHERE hash IN (SELECT hash FROM open_platform.tokens WHERE expires_at <= $1 ORDER BY expires_at,hash LIMIT $2 FOR UPDATE SKIP LOCKED)`, now},
		{`DELETE FROM open_platform.consents WHERE id IN (SELECT id FROM open_platform.consents WHERE expires_at <= $1 ORDER BY expires_at,id LIMIT $2 FOR UPDATE SKIP LOCKED)`, now.Add(-24 * time.Hour)},
		{`DELETE FROM open_platform.events WHERE id IN (SELECT id FROM open_platform.events WHERE created_at <= $1 ORDER BY created_at,id LIMIT $2 FOR UPDATE SKIP LOCKED)`, now.AddDate(-1, 0, 0)},
		{`DELETE FROM open_platform.notices WHERE id IN (SELECT id FROM open_platform.notices WHERE created_at <= $1 ORDER BY created_at,id LIMIT $2 FOR UPDATE SKIP LOCKED)`, now.AddDate(-1, 0, 0)},
		{`DELETE FROM open_platform.quotas WHERE (app_id,day) IN (SELECT app_id,day FROM open_platform.quotas WHERE day < to_char($1::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD') ORDER BY day,app_id LIMIT $2 FOR UPDATE SKIP LOCKED)`, now.Add(-24 * time.Hour)},
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
