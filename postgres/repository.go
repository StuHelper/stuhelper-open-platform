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
	var ok bool
	e := r.DB.QueryRowContext(ctx, `SELECT to_regclass('open_platform.apps') IS NOT NULL AND to_regclass('open_platform.notices') IS NOT NULL`).Scan(&ok)
	if e != nil || !ok {
		return op.ErrUnavailable
	}
	return nil
}
func (r *Repository) CheckRuntime(ctx context.Context) error {
	var unsafe bool
	e := r.DB.QueryRowContext(ctx, `SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR has_schema_privilege(current_user,'open_platform','CREATE') OR has_table_privilege(current_user,'open_platform.events','UPDATE') OR has_table_privilege(current_user,'open_platform.requests','UPDATE') OR has_table_privilege(current_user,'open_platform.tokens','UPDATE') FROM pg_roles WHERE rolname=current_user`).Scan(&unsafe)
	if e != nil || unsafe {
		return op.ErrUnavailable
	}
	return r.Ready(ctx)
}
func (r *Repository) Transaction(ctx context.Context, owner, app string, run func(op.Transaction) error) error {
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
		if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-platform-app:"+app); e != nil {
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
func (t *transaction) CloseOwner(owner, id string) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.owners VALUES($1,true,$2) ON CONFLICT(owner_key) DO UPDATE SET closed=true WHERE open_platform.owners.closure_id=EXCLUDED.closure_id`, owner, id)
	if e != nil {
		return safe(e)
	}
	var old string
	e = t.tx.QueryRowContext(t.ctx, `SELECT closure_id FROM open_platform.owners WHERE owner_key=$1`, owner).Scan(&old)
	if e == nil && old != id {
		return op.ErrConflict
	}
	return safe(e)
}
func (t *transaction) App(id string) (op.AppRecord, error) {
	var out op.AppRecord
	var raw []byte
	e := t.tx.QueryRowContext(t.ctx, `SELECT owner_key,secret_hash,document FROM open_platform.apps WHERE id=$1`, id).Scan(&out.Owner, &out.SecretHash, &raw)
	if e != nil {
		return out, safe(e)
	}
	if json.Unmarshal(raw, &out.View) != nil {
		return out, op.ErrUnavailable
	}
	return out, nil
}
func (t *transaction) Apps(owner string, admin bool, after string, limit int) ([]op.AppRecord, error) {
	rows, e := t.tx.QueryContext(t.ctx, `SELECT owner_key,secret_hash,document FROM open_platform.apps WHERE ($2 OR owner_key=$1) AND id>$3 ORDER BY id LIMIT $4`, owner, admin, after, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.AppRecord{}
	for rows.Next() {
		var a op.AppRecord
		var b []byte
		if e = rows.Scan(&a.Owner, &a.SecretHash, &b); e != nil {
			return nil, safe(e)
		}
		if json.Unmarshal(b, &a.View) != nil {
			return nil, op.ErrUnavailable
		}
		out = append(out, a)
	}
	return out, safe(rows.Err())
}
func (t *transaction) SaveApp(a op.AppRecord) error {
	raw, e := encode(a.View)
	if e != nil {
		return op.ErrUnavailable
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.apps VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state,revision=EXCLUDED.revision,secret_hash=EXCLUDED.secret_hash,document=EXCLUDED.document`, a.View.ID, a.Owner, a.View.State, a.View.Revision, a.SecretHash, raw)
	return safe(e)
}
func (t *transaction) CountApps(owner string) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM open_platform.apps WHERE owner_key=$1`, owner).Scan(&n)
	return n, safe(e)
}
func (t *transaction) SuspendOwnedApps(owner string) error {
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
		a.View.State = "suspended"
		a.View.Revision++
		a.View.Note = "owner_account_closed"
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
	return decode[op.ConsentRecord](r.DB.QueryRowContext(ctx, `SELECT document FROM open_platform.consents WHERE id=$1`, id))
}
func (r *Repository) LocateCode(ctx context.Context, h string) (op.ConsentRecord, error) {
	return decode[op.ConsentRecord](r.DB.QueryRowContext(ctx, `SELECT document FROM open_platform.consents WHERE code_hash=$1`, h))
}
func (t *transaction) Grant(id string) (op.GrantRecord, error) {
	return decode[op.GrantRecord](t.tx.QueryRowContext(t.ctx, `SELECT document FROM open_platform.grants WHERE id=$1`, id))
}
func (t *transaction) OwnerGrant(owner, app string) (op.GrantRecord, error) {
	return decode[op.GrantRecord](t.tx.QueryRowContext(t.ctx, `SELECT document FROM open_platform.grants WHERE owner_key=$1 AND app_id=$2`, owner, app))
}
func (r *Repository) LocateGrant(ctx context.Context, id string) (op.GrantRecord, error) {
	return decode[op.GrantRecord](r.DB.QueryRowContext(ctx, `SELECT document FROM open_platform.grants WHERE id=$1`, id))
}
func (t *transaction) Grants(owner, after string, limit int) ([]op.GrantRecord, error) {
	rows, e := t.tx.QueryContext(t.ctx, `SELECT document FROM open_platform.grants WHERE owner_key=$1 AND id>$2 ORDER BY id LIMIT $3`, owner, after, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.GrantRecord{}
	for rows.Next() {
		v, e := decode[op.GrantRecord](rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, safe(rows.Err())
}
func (t *transaction) SaveGrant(g op.GrantRecord) error {
	raw, e := encode(g)
	if e != nil {
		return op.ErrUnavailable
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.grants VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET app_revision=EXCLUDED.app_revision,state=EXCLUDED.state,expires_at=EXCLUDED.expires_at,document=EXCLUDED.document`, g.View.ID, g.View.AppID, g.Owner, g.AppRevision, g.View.State, g.View.ExpiresAt, raw)
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
	v, e := decode[op.TokenRecord](r.DB.QueryRowContext(ctx, `SELECT document FROM open_platform.tokens WHERE hash=$1`, h))
	if e != nil {
		return v, op.GrantRecord{}, e
	}
	g, e := r.LocateGrant(ctx, v.GrantID)
	return v, g, e
}
func (t *transaction) Quota(app, day string, limit int) error {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `INSERT INTO open_platform.quotas VALUES($1,$2,1) ON CONFLICT(app_id,day) DO UPDATE SET used=open_platform.quotas.used+1 WHERE open_platform.quotas.used<$3 RETURNING used`, app, day, limit).Scan(&n)
	if errors.Is(e, sql.ErrNoRows) {
		return op.ErrQuota
	}
	return safe(e)
}
func (t *transaction) Notice(id string) (op.Notice, error) {
	return decode[op.Notice](t.tx.QueryRowContext(t.ctx, `SELECT jsonb_set(document,'{sequence}',to_jsonb(position)) FROM open_platform.notices WHERE id=$1`, id))
}
func (t *transaction) Notices(app, after string, limit int) ([]op.Notice, error) {
	rows, e := t.tx.QueryContext(t.ctx, `SELECT jsonb_set(document,'{sequence}',to_jsonb(position)) FROM open_platform.notices WHERE app_id=$1 AND position>COALESCE(NULLIF($2,'')::bigint,0) ORDER BY position LIMIT $3`, app, after, limit)
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
func (t *transaction) SaveReplay(actor, key, digest string, result json.RawMessage) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.requests(actor,key,digest,result) VALUES($1,$2,$3,$4)`, actor, key, digest, string(result))
	return safe(e)
}
func (t *transaction) Event(actor, kind, object, key string) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO open_platform.events(actor,kind,object_id,operation) VALUES($1,$2,$3,$4)`, actor, kind, object, key)
	return safe(e)
}
func (r *Repository) WorkCandidates(ctx context.Context, now time.Time, limit int) ([]op.GrantRecord, error) {
	rows, e := r.DB.QueryContext(ctx, `SELECT g.document FROM open_platform.grants g JOIN open_platform.apps a ON a.id=g.app_id LEFT JOIN open_platform.owners u ON u.owner_key=g.owner_key LEFT JOIN open_platform.owners d ON d.owner_key=a.owner_key WHERE g.state='active' AND (g.expires_at<=$1 OR g.app_revision<>a.revision OR a.state<>'active' OR u.closed OR d.closed) ORDER BY g.id LIMIT $2`, now, limit)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []op.GrantRecord{}
	for rows.Next() {
		v, e := decode[op.GrantRecord](rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, safe(rows.Err())
}

func (t *transaction) PendingConsents(owner string, now time.Time) (int, error) {
	var n int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM open_platform.consents WHERE owner_key=$1 AND COALESCE(document->>'Decision','')='' AND (document->'View'->>'expires_at')::timestamptz>$2`, owner, now).Scan(&n)
	return n, safe(e)
}
