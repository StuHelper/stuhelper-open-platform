package postgres

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"time"
)

//go:embed schema.sql
var Schema string

type Repository struct{ DB *sql.DB }
type transaction struct {
	ctx context.Context
	tx  *sql.Tx
}

func safe(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, sql.ErrNoRows) {
		return op.ErrNotFound
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return e
	}
	var p *pgconn.PgError
	if errors.As(e, &p) && (p.Code == "23505" || p.Code == "40001" || p.Code == "40P01") {
		return op.ErrConflict
	}
	return op.ErrUnavailable
}
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(726391840120)`); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, Schema); e != nil {
		return e
	}
	return tx.Commit()
}
func (r *Repository) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var ok bool
	e := r.DB.QueryRowContext(ctx, `SELECT to_regclass('open_platform.apps') IS NOT NULL AND to_regclass('open_platform.notices') IS NOT NULL`).Scan(&ok)
	if e != nil || !ok {
		return op.ErrUnavailable
	}
	return nil
}
func (r *Repository) CheckRuntime(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var unsafe bool
	e := r.DB.QueryRowContext(ctx, `SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR has_schema_privilege(current_user,'open_platform','CREATE') OR has_table_privilege(current_user,'open_platform.events','UPDATE') OR has_table_privilege(current_user,'open_platform.requests','UPDATE') OR has_table_privilege(current_user,'open_platform.tokens','UPDATE') FROM pg_roles WHERE rolname=current_user`).Scan(&unsafe)
	if e != nil || unsafe {
		return op.ErrUnavailable
	}
	return r.Ready(ctx)
}
func (r *Repository) Transaction(ctx context.Context, owner, app string, exclusiveApp bool, run func(op.Transaction) error) error {
	tx, e := r.DB.BeginTx(ctx, nil)
	if e != nil {
		return safe(e)
	}
	defer tx.Rollback()
	// All paths lock the grant owner before the application. Closure can fence an owner without locking every grant.
	if owner != "" {
		if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-platform-owner:"+owner); e != nil {
			return safe(e)
		}
	}
	if app != "" {
		lockSQL := `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`
		if exclusiveApp {
			lockSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`
		}
		if _, e = tx.ExecContext(ctx, lockSQL, "open-platform-app:"+app); e != nil {
			return safe(e)
		}
	}
	if e = run(&transaction{ctx, tx}); e != nil {
		return e
	}
	return safe(tx.Commit())
}

type scanner interface{ Scan(...any) error }

func decode[T any](row scanner) (T, error) {
	var out T
	var raw []byte
	if e := row.Scan(&raw); e != nil {
		return out, safe(e)
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, op.ErrUnavailable
	}
	return out, nil
}
func encode(v any) (string, error) { b, e := json.Marshal(v); return string(b), e }
func (t *transaction) Closed(owner string) (bool, error) {
	var closed bool
	e := t.tx.QueryRowContext(t.ctx, `SELECT COALESCE((SELECT closed FROM open_platform.owners WHERE owner_key=$1),false)`, owner).Scan(&closed)
	return closed, safe(e)
}
func (t *transaction) CloseOwner(owner, id string, at time.Time) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.owners(owner_key,closed,closure_id,closed_at) VALUES($1,true,$2,$3) ON CONFLICT(owner_key) DO UPDATE SET closed=true WHERE open_platform.owners.closure_id=EXCLUDED.closure_id`, owner, id, at)
	if e != nil {
		return safe(e)
	}
	var old string
	e = t.tx.QueryRowContext(t.ctx, `SELECT closure_id FROM open_platform.owners WHERE owner_key=$1`, owner).Scan(&old)
	if e == nil && old != id {
		return op.WithReason(op.ErrConflict, "idempotency_conflict")
	}
	return safe(e)
}
func (r *Repository) LocateApp(ctx context.Context, id string) (op.AppRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return decodeAppRecord(r.DB.QueryRowContext(ctx, `SELECT owner_key,secret_hash,updated_at,reviewed_by,reviewed_at,document,terminated_at FROM open_platform.apps WHERE id=$1`, id))
}
func decodeAppRecord(row scanner) (op.AppRecord, error) {
	var out op.AppRecord
	var raw []byte
	var updatedAt time.Time
	var reviewedAt sql.NullTime
	if e := row.Scan(&out.Owner, &out.SecretHash, &updatedAt, &out.ReviewedBy, &reviewedAt, &raw, &out.TerminatedAt); e != nil {
		return out, safe(e)
	}
	if json.Unmarshal(raw, &out.View) != nil {
		return out, op.ErrUnavailable
	}
	out.UpdatedAt = updatedAt.UTC()
	if reviewedAt.Valid {
		at := reviewedAt.Time.UTC()
		out.ReviewedAt = &at
	}
	return out, nil
}
func toAdminApp(a op.AppRecord, activeGrants int) op.AdminApplication {
	return op.AdminApplication{
		ID:                 a.View.ID,
		Owner:              a.Owner,
		Name:               a.View.Name,
		Purpose:            a.View.Purpose,
		RedirectURIs:       append([]string{}, a.View.RedirectURIs...),
		RequestedScopes:    append([]string{}, a.View.RequestedScopes...),
		ApprovedScopes:     append([]string{}, a.View.ApprovedScopes...),
		ClientType:         a.View.ClientType,
		State:              a.View.State,
		Note:               a.View.Note,
		Revision:           a.View.Revision,
		CredentialRevision: a.View.CredentialRevision,
		Policy:             a.View.Policy,
		ActiveGrants:       activeGrants,
		ReviewedBy:         a.ReviewedBy,
		ReviewedAt:         a.ReviewedAt,
		CreatedAt:          a.View.CreatedAt,
		UpdatedAt:          a.UpdatedAt,
	}
}
func (t *transaction) App(id string) (op.AppRecord, error) {
	return decodeAppRecord(t.tx.QueryRowContext(t.ctx, `SELECT owner_key,secret_hash,updated_at,reviewed_by,reviewed_at,document,terminated_at FROM open_platform.apps WHERE id=$1`, id))
}
func (t *transaction) Apps(owner string, admin bool, after string, limit int) ([]op.AppRecord, error) {
	rows, e := t.tx.QueryContext(t.ctx, `SELECT owner_key,secret_hash,updated_at,reviewed_by,reviewed_at,document,terminated_at FROM open_platform.apps WHERE ($2 OR owner_key=$1) AND id>$3 ORDER BY id LIMIT $4`, owner, admin, after, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.AppRecord{}
	for rows.Next() {
		a, e := decodeAppRecord(rows)
		if e != nil {
			return nil, e
		}

		out = append(out, a)
	}
	return out, safe(rows.Err())
}
func (t *transaction) AdminApp(id string, now time.Time) (op.AdminApplication, error) {
	var raw []byte
	var rec op.AppRecord
	var updatedAt time.Time
	var reviewedAt sql.NullTime
	var activeGrants int
	e := t.tx.QueryRowContext(t.ctx, `
SELECT a.owner_key, a.secret_hash, a.updated_at, a.reviewed_by, a.reviewed_at, a.document,
	CASE WHEN a.state='active' AND NOT COALESCE(d.closed,false) THEN (
		SELECT count(*) FROM open_platform.grants g
		LEFT JOIN open_platform.owners u ON u.owner_key=g.owner_key
		WHERE g.app_id=a.id AND g.state='active' AND g.app_revision=a.revision AND g.expires_at>$2 AND NOT COALESCE(u.closed,false)
	) ELSE 0 END
FROM open_platform.apps a
LEFT JOIN open_platform.owners d ON d.owner_key=a.owner_key
WHERE a.id=$1`, id, now).Scan(&rec.Owner, &rec.SecretHash, &updatedAt, &rec.ReviewedBy, &reviewedAt, &raw, &activeGrants)
	if e != nil {
		return op.AdminApplication{}, safe(e)
	}
	if json.Unmarshal(raw, &rec.View) != nil {
		return op.AdminApplication{}, op.ErrUnavailable
	}
	rec.UpdatedAt = updatedAt.UTC()
	if reviewedAt.Valid {
		at := reviewedAt.Time.UTC()
		rec.ReviewedAt = &at
	}
	return toAdminApp(rec, activeGrants), nil
}
func (t *transaction) AdminApps(state, owner string, now time.Time, cursor op.AppCursor, limit int) ([]op.AdminApplication, error) {
	rows, e := t.tx.QueryContext(t.ctx, `
SELECT a.owner_key, a.secret_hash, a.updated_at, a.reviewed_by, a.reviewed_at, a.document,
	CASE WHEN a.state='active' AND NOT COALESCE(d.closed,false) THEN (
		SELECT count(*) FROM open_platform.grants g
		LEFT JOIN open_platform.owners u ON u.owner_key=g.owner_key
		WHERE g.app_id=a.id AND g.state='active' AND g.app_revision=a.revision AND g.expires_at>$3 AND NOT COALESCE(u.closed,false)
	) ELSE 0 END
FROM open_platform.apps a
LEFT JOIN open_platform.owners d ON d.owner_key=a.owner_key
WHERE ($1='' OR a.state=$1)
  AND ($2='' OR a.owner_key=$2)
  AND (NOT $4 OR a.updated_at<$5 OR (a.updated_at=$5 AND a.id<$6))
ORDER BY a.updated_at DESC, a.id DESC
LIMIT $7`, state, owner, now, cursor.Set, cursor.UpdatedAt, cursor.ID, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.AdminApplication{}
	for rows.Next() {
		var raw []byte
		var rec op.AppRecord
		var updatedAt time.Time
		var reviewedAt sql.NullTime
		var activeGrants int
		if e = rows.Scan(&rec.Owner, &rec.SecretHash, &updatedAt, &rec.ReviewedBy, &reviewedAt, &raw, &activeGrants); e != nil {
			return nil, safe(e)
		}
		if json.Unmarshal(raw, &rec.View) != nil {
			return nil, op.ErrUnavailable
		}
		rec.UpdatedAt = updatedAt.UTC()
		if reviewedAt.Valid {
			at := reviewedAt.Time.UTC()
			rec.ReviewedAt = &at
		}
		out = append(out, toAdminApp(rec, activeGrants))
	}
	return out, safe(rows.Err())
}
func (t *transaction) SaveApp(a op.AppRecord) error {
	if a.UpdatedAt.IsZero() {
		if !a.View.CreatedAt.IsZero() {
			a.UpdatedAt = a.View.CreatedAt.UTC().Truncate(time.Microsecond)
		} else {
			a.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
		}
	}
	raw, e := encode(a.View)
	if e != nil {
		return op.ErrUnavailable
	}
	updatedAt := a.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = a.View.CreatedAt
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.invalid_revisions(app_id,revision,invalidated_at)
        SELECT a.id,a.revision,$4 FROM open_platform.apps a WHERE a.id=$1 AND (a.revision,a.state) IS DISTINCT FROM ($2,$3)
        AND EXISTS (SELECT 1 FROM open_platform.grants g WHERE g.app_id=a.id AND g.app_revision=a.revision AND g.state='active')
        ON CONFLICT DO NOTHING`, a.View.ID, a.View.Revision, a.View.State, updatedAt)
	if e != nil {
		return safe(e)
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.apps(id,owner_key,state,revision,secret_hash,document,updated_at,terminated_at,reviewed_by,reviewed_at,archived_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO UPDATE SET revision_work_pending=open_platform.apps.revision_work_pending OR ((open_platform.apps.revision,open_platform.apps.state) IS DISTINCT FROM (EXCLUDED.revision,EXCLUDED.state) AND EXISTS (SELECT 1 FROM open_platform.grants g WHERE g.app_id=EXCLUDED.id AND g.state='active')),state=EXCLUDED.state,revision=EXCLUDED.revision,secret_hash=EXCLUDED.secret_hash,document=EXCLUDED.document,updated_at=EXCLUDED.updated_at,terminated_at=EXCLUDED.terminated_at,reviewed_by=EXCLUDED.reviewed_by,reviewed_at=EXCLUDED.reviewed_at,archived_at=EXCLUDED.archived_at`, a.View.ID, a.Owner, a.View.State, a.View.Revision, a.SecretHash, raw, updatedAt, a.TerminatedAt, a.ReviewedBy, a.ReviewedAt, a.View.ArchivedAt)
	return safe(e)
}
func (t *transaction) CountApps(owner string) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM open_platform.apps WHERE owner_key=$1`, owner).Scan(&n)
	return n, safe(e)
}
func (t *transaction) SuspendOwnedApps(owner string, at time.Time) error {
	// Application creation is bounded at 100 per owner. Row locks serialize the epoch bump with administrator decisions.
	rows, e := t.Apps(owner, false, "", 101)
	if e != nil {
		return e
	}
	if len(rows) > 100 {
		return op.ErrUnavailable
	}
	for _, row := range rows {
		if _, e = t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-platform-app:"+row.View.ID); e != nil {
			return safe(e)
		}
		a, e := t.App(row.View.ID)
		if e != nil {
			return e
		}
		ts := at.UTC()
		a.View.State = "suspended"
		a.View.Revision++
		a.View.Note = "owner_account_closed"
		a.UpdatedAt = ts
		a.TerminatedAt = &ts
		if e = t.SaveApp(a); e != nil {
			return e
		}
	}
	return nil
}
func (t *transaction) Consent(id string) (op.ConsentRecord, error) {
	return decode[op.ConsentRecord](t.tx.QueryRowContext(t.ctx, `SELECT document FROM open_platform.consents WHERE id=$1`, id))
}
func (t *transaction) SaveConsent(c op.ConsentRecord) error {
	raw, e := encode(c)
	if e != nil {
		return op.ErrUnavailable
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.consents(id,owner_key,app_id,code_hash,document,expires_at) VALUES($1,$2,$3,NULLIF($4,''),$5,$6) ON CONFLICT(id) DO UPDATE SET code_hash=EXCLUDED.code_hash,document=EXCLUDED.document,expires_at=EXCLUDED.expires_at`, c.View.ID, c.Owner, c.Input.ClientID, c.CodeHash, raw, c.View.ExpiresAt)
	return safe(e)
}
func (r *Repository) LocateConsent(ctx context.Context, id string) (op.ConsentRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return decode[op.ConsentRecord](r.DB.QueryRowContext(ctx, `SELECT document FROM open_platform.consents WHERE id=$1`, id))
}
func (r *Repository) LocateCode(ctx context.Context, h string) (op.ConsentRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return decode[op.ConsentRecord](r.DB.QueryRowContext(ctx, `SELECT document FROM open_platform.consents WHERE code_hash=$1`, h))
}
func decodeGrant(row scanner) (op.GrantRecord, error) {
	var out op.GrantRecord
	var raw []byte
	var grantedAt, updatedAt time.Time
	var lastReadAt sql.NullTime
	if e := row.Scan(&raw, &grantedAt, &updatedAt, &lastReadAt); e != nil {
		return out, safe(e)
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, op.ErrUnavailable
	}
	out.View.GrantedAt = grantedAt.UTC()
	out.View.UpdatedAt = updatedAt.UTC()
	if lastReadAt.Valid {
		at := lastReadAt.Time.UTC()
		out.View.LastDataReadAt = &at
	} else {
		out.View.LastDataReadAt = nil
	}
	return out, nil
}
func (t *transaction) Grant(id string) (op.GrantRecord, error) {
	return decodeGrant(t.tx.QueryRowContext(t.ctx, `SELECT document,granted_at,updated_at,last_data_read_at FROM open_platform.grants WHERE id=$1`, id))
}
func (t *transaction) OwnerGrant(owner, app string) (op.GrantRecord, error) {
	return decodeGrant(t.tx.QueryRowContext(t.ctx, `SELECT document,granted_at,updated_at,last_data_read_at FROM open_platform.grants WHERE owner_key=$1 AND app_id=$2`, owner, app))
}
func (r *Repository) LocateGrant(ctx context.Context, id string) (op.GrantRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return decodeGrant(r.DB.QueryRowContext(ctx, `SELECT document,granted_at,updated_at,last_data_read_at FROM open_platform.grants WHERE id=$1`, id))
}
func (t *transaction) Grants(owner, after string, limit int) ([]op.GrantSummary, error) {
	rows, e := t.tx.QueryContext(t.ctx, `SELECT g.document,a.state,a.revision,COALESCE(u.closed,false),COALESCE(d.closed,false) FROM open_platform.grants g JOIN open_platform.apps a ON a.id=g.app_id LEFT JOIN open_platform.owners u ON u.owner_key=g.owner_key LEFT JOIN open_platform.owners d ON d.owner_key=a.owner_key WHERE g.owner_key=$1 AND g.id>$2 ORDER BY g.id LIMIT $3`, owner, after, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.GrantSummary{}
	for rows.Next() {
		var item op.GrantSummary
		var raw []byte
		if e = rows.Scan(&raw, &item.AppState, &item.CurrentAppRev, &item.OwnerClosed, &item.AppOwnerClosed); e != nil {
			return nil, safe(e)
		}
		if json.Unmarshal(raw, &item.Record) != nil {
			return nil, op.ErrUnavailable
		}
		out = append(out, item)
	}
	return out, safe(rows.Err())
}
func (t *transaction) ListGrants(owner, state string, now time.Time, cursor op.GrantCursor, limit int) ([]op.GrantListEntry, error) {
	rows, e := t.tx.QueryContext(t.ctx, `
WITH evaluated AS (
	SELECT g.id, g.document, g.granted_at, g.updated_at, g.last_data_read_at,
		a.state AS app_state, a.revision AS current_app_revision,
		(COALESCE(u.closed, false) OR COALESCE(d.closed, false)) AS owner_closed,
		CASE WHEN g.state='active' AND g.expires_at>$2 AND a.state='active' AND g.app_revision=a.revision AND NOT COALESCE(u.closed,false) AND NOT COALESCE(d.closed,false) THEN 0 ELSE 1 END AS active_rank
	FROM open_platform.grants g
	JOIN open_platform.apps a ON a.id=g.app_id
	LEFT JOIN open_platform.owners u ON u.owner_key=g.owner_key
	LEFT JOIN open_platform.owners d ON d.owner_key=a.owner_key
	WHERE g.owner_key=$1
)
SELECT document, granted_at, updated_at, last_data_read_at, app_state, current_app_revision, owner_closed
FROM evaluated
WHERE ($3='' OR ($3='active' AND active_rank=0) OR ($3='revoked' AND active_rank=1))
  AND (NOT $4 OR active_rank>$5 OR (active_rank=$5 AND updated_at<$6) OR (active_rank=$5 AND updated_at=$6 AND id<$7))
ORDER BY active_rank ASC, updated_at DESC, id DESC
LIMIT $8`, owner, now, state, cursor.Set, cursor.Rank, cursor.UpdatedAt, cursor.ID, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.GrantListEntry{}
	for rows.Next() {
		var entry op.GrantListEntry
		var raw []byte
		var grantedAt, updatedAt time.Time
		var lastReadAt sql.NullTime
		if e = rows.Scan(&raw, &grantedAt, &updatedAt, &lastReadAt, &entry.AppState, &entry.CurrentAppRevision, &entry.OwnerClosed); e != nil {
			return nil, safe(e)
		}
		if json.Unmarshal(raw, &entry.Record) != nil {
			return nil, op.ErrUnavailable
		}
		entry.Record.View.GrantedAt = grantedAt.UTC()
		entry.Record.View.UpdatedAt = updatedAt.UTC()
		if lastReadAt.Valid {
			at := lastReadAt.Time.UTC()
			entry.Record.View.LastDataReadAt = &at
		}
		out = append(out, entry)
	}
	return out, safe(rows.Err())
}
func (t *transaction) SaveGrant(g op.GrantRecord) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	if g.View.GrantedAt.IsZero() {
		g.View.GrantedAt = now
	}
	if g.View.UpdatedAt.IsZero() {
		g.View.UpdatedAt = g.View.GrantedAt
	}
	raw, e := encode(g)
	if e != nil {
		return op.ErrUnavailable
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.grants(id,app_id,owner_key,app_revision,state,expires_at,granted_at,updated_at,document,terminated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(id) DO UPDATE SET app_revision=EXCLUDED.app_revision,state=EXCLUDED.state,expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at,document=EXCLUDED.document,terminated_at=EXCLUDED.terminated_at`, g.View.ID, g.View.AppID, g.Owner, g.AppRevision, g.View.State, g.View.ExpiresAt, g.View.GrantedAt, g.View.UpdatedAt, raw, g.TerminatedAt)
	return safe(e)
}
func (t *transaction) TouchGrantRead(id string, at time.Time) error {
	_, e := t.tx.ExecContext(t.ctx, `UPDATE open_platform.grants SET last_data_read_at=$2 WHERE id=$1 AND (last_data_read_at IS NULL OR last_data_read_at<=$2::timestamptz-interval '1 minute')`, id, at)
	return safe(e)
}
func (t *transaction) Token(h string) (op.TokenRecord, error) {
	return decode[op.TokenRecord](t.tx.QueryRowContext(t.ctx, `SELECT document FROM open_platform.tokens WHERE hash=$1`, h))
}
func (t *transaction) SaveToken(v op.TokenRecord) error {
	raw, e := encode(v)
	if e != nil {
		return op.ErrUnavailable
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.tokens(hash,grant_id,document,expires_at) VALUES($1,$2,$3,$4)`, v.Hash, v.GrantID, raw, v.ExpiresAt)
	return safe(e)
}
func (r *Repository) LocateToken(ctx context.Context, h string) (op.TokenRecord, op.GrantRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, e := decode[op.TokenRecord](r.DB.QueryRowContext(ctx, `SELECT document FROM open_platform.tokens WHERE hash=$1`, h))
	if e != nil {
		return v, op.GrantRecord{}, e
	}
	g, e := r.LocateGrant(ctx, v.GrantID)
	return v, g, e
}
func (t *transaction) Quota(app, day string, limit int) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `INSERT INTO open_platform.quotas VALUES($1,$2,1) ON CONFLICT(app_id,day) DO UPDATE SET used=open_platform.quotas.used+1 WHERE open_platform.quotas.used<$3 RETURNING used`, app, day, limit).Scan(&n)
	if errors.Is(e, sql.ErrNoRows) {
		return limit, op.WithReason(op.ErrQuota, "daily_quota_exceeded")
	}
	return n, safe(e)
}
func (t *transaction) QuotaUsed(app, day string) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT COALESCE((SELECT used FROM open_platform.quotas WHERE app_id=$1 AND day=$2),0)`, app, day).Scan(&n)
	return n, safe(e)
}
func (t *transaction) LockAppAck(app string) error {
	_, e := t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-platform-app-ack:"+app)
	return safe(e)
}
func (t *transaction) Notice(id string) (op.Notice, error) {
	return decode[op.Notice](t.tx.QueryRowContext(t.ctx, `SELECT jsonb_set(document,'{sequence}',to_jsonb(position)) FROM open_platform.notices WHERE id=$1`, id))
}
func (t *transaction) Notices(app string, pendingAck bool, after string, limit int) ([]op.Notice, error) {
	rows, e := t.tx.QueryContext(t.ctx, `SELECT jsonb_set(document,'{sequence}',to_jsonb(position)) FROM open_platform.notices WHERE app_id=$1 AND position>COALESCE(NULLIF($2,'')::bigint,0) AND (NOT $3 OR COALESCE(document->>'acknowledgement','') NOT IN ('deleted','retention_exception')) ORDER BY position LIMIT $4`, app, after, pendingAck, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.Notice{}
	for rows.Next() {
		v, e := decode[op.Notice](rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, safe(rows.Err())
}
func (t *transaction) OverdueNoticeApps(cutoff time.Time, cursor op.OverdueCursor, limit int) ([]op.OverdueNoticeApplication, error) {
	rows, e := t.tx.QueryContext(t.ctx, `
WITH grouped AS (
	SELECT n.app_id, count(*)::int AS overdue_notices, min(n.created_at) AS oldest_notice_at
	FROM open_platform.notices n
	WHERE COALESCE(n.document->>'acknowledgement','') NOT IN ('deleted','retention_exception')
	  AND n.created_at <= $1
	GROUP BY n.app_id
)
SELECT g.app_id, COALESCE(a.document->>'name',''), a.owner_key, a.state, g.overdue_notices, g.oldest_notice_at
FROM grouped g
JOIN open_platform.apps a ON a.id=g.app_id
WHERE NOT $2 OR g.oldest_notice_at>$3 OR (g.oldest_notice_at=$3 AND g.app_id>$4)
ORDER BY g.oldest_notice_at ASC, g.app_id ASC
LIMIT $5`, cutoff, cursor.Set, cursor.OldestNoticeAt, cursor.AppID, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.OverdueNoticeApplication{}
	for rows.Next() {
		var v op.OverdueNoticeApplication
		if e = rows.Scan(&v.AppID, &v.AppName, &v.Owner, &v.State, &v.OverdueNotices, &v.OldestNoticeAt); e != nil {
			return nil, safe(e)
		}
		v.OldestNoticeAt = v.OldestNoticeAt.UTC()
		out = append(out, v)
	}
	return out, safe(rows.Err())
}
func (t *transaction) MarkNoticesSeen(ids []string, seenAt time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, e := t.tx.ExecContext(t.ctx, `UPDATE open_platform.notices SET document=jsonb_set(document,'{seen_at}',to_jsonb($2::timestamptz)) WHERE id=ANY($1) AND document->'seen_at' IS NULL`, ids, seenAt)
	return safe(e)
}
func (t *transaction) SaveNotice(n op.Notice) error {
	raw, e := encode(n)
	if e != nil {
		return op.ErrUnavailable
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.notices(id,app_id,document,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document`, n.ID, n.AppID, raw, n.CreatedAt)
	return safe(e)
}
func (t *transaction) Replay(actor, key string) (string, json.RawMessage, error) {
	var h string
	var b []byte
	e := t.tx.QueryRowContext(t.ctx, `SELECT digest,result FROM open_platform.requests WHERE actor=$1 AND key=$2`, actor, key).Scan(&h, &b)
	return h, b, safe(e)
}
func (t *transaction) SaveReplay(actor, key, digest string, result json.RawMessage, at time.Time) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.requests(actor,key,digest,result,created_at) VALUES($1,$2,$3,$4,$5)`, actor, key, digest, string(result), at)
	return safe(e)
}
func (t *transaction) Event(actor, kind, object, key, reason string, at time.Time) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.events(actor,kind,object_id,operation,reason,result,created_at) VALUES($1,$2,$3,$4,$5,'success',$6)`, actor, kind, object, key, reason, at)
	return safe(e)
}
func (r *Repository) WorkCandidates(ctx context.Context, now time.Time, limit int) ([]op.GrantRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, e := r.DB.QueryContext(ctx, `WITH pending AS MATERIALIZED (
        SELECT id,revision,state FROM open_platform.apps WHERE revision_work_pending ORDER BY id LIMIT $2
    ), invalid AS MATERIALIZED (
        SELECT a.id AS app_id, stale.id FROM pending a CROSS JOIN LATERAL (
            (SELECT id FROM open_platform.grants WHERE app_id=a.id AND state='active' AND a.state<>'active' ORDER BY app_revision,id LIMIT $2)
            UNION ALL
            (SELECT id FROM open_platform.grants WHERE app_id=a.id AND state='active' AND a.state='active' AND app_revision<a.revision ORDER BY app_revision,id LIMIT $2)
            UNION ALL
            (SELECT id FROM open_platform.grants WHERE app_id=a.id AND state='active' AND a.state='active' AND app_revision>a.revision ORDER BY app_revision DESC,id LIMIT $2)
        ) stale
    ), drained AS (
        UPDATE open_platform.apps a SET revision_work_pending=false FROM pending p
        WHERE a.id=p.id AND a.revision=p.revision AND a.state=p.state
          AND NOT EXISTS (SELECT 1 FROM invalid i WHERE i.app_id=p.id)
    ), cleared_revisions AS (
        DELETE FROM open_platform.invalid_revisions WHERE (app_id,revision) IN (
            SELECT i.app_id,i.revision FROM open_platform.invalid_revisions i
            WHERE NOT EXISTS (SELECT 1 FROM open_platform.grants g WHERE g.state='active' AND g.app_id=i.app_id AND g.app_revision=i.revision)
            LIMIT $2)
    ), candidates AS (
        (SELECT g.id FROM open_platform.grants g WHERE g.state='active' AND g.expires_at<=$1 ORDER BY g.expires_at,g.id LIMIT $2)
        UNION
        (SELECT id FROM invalid LIMIT $2)
        UNION
        (SELECT g.id FROM open_platform.owners u JOIN LATERAL (SELECT g.id FROM open_platform.grants g WHERE g.state='active' AND g.owner_key=u.owner_key ORDER BY g.id LIMIT $2) g ON true WHERE u.closed LIMIT $2)
		UNION
		(SELECT g.id FROM open_platform.owners d JOIN open_platform.apps a ON a.owner_key=d.owner_key JOIN LATERAL (SELECT g.id FROM open_platform.grants g WHERE g.state='active' AND g.app_id=a.id ORDER BY g.app_revision,g.id LIMIT $2) g ON true WHERE d.closed LIMIT $2)
	)
	SELECT g.document,g.granted_at,g.updated_at,g.last_data_read_at FROM open_platform.grants g JOIN (SELECT id FROM candidates ORDER BY id LIMIT $2) c ON c.id=g.id ORDER BY g.id`, now, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.GrantRecord{}
	for rows.Next() {
		v, e := decodeGrant(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, safe(rows.Err())
}

func (t *transaction) PendingConsents(owner string, now time.Time) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM open_platform.consents WHERE owner_key=$1 AND COALESCE(document->>'Decision','')='' AND expires_at>$2`, owner, now).Scan(&n)
	return n, safe(e)
}
