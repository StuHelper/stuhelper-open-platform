package openplatform_test

import "testing"

func TestCleanupAppliesIndependentBatchesAcrossEightCategories(t *testing.T) {
	x := setup(t)
	expired := x.s.Now().AddDate(-2, 0, 0)
	// An archived parent can be removed after its final grant, while the active
	// app keeps serving as the parent of the consent, notice, and quota fixtures.
	for _, seed := range []struct {
		table string
		query string
	}{
		{"apps", `
			INSERT INTO open_platform.apps (id, owner_key, state, revision, secret_hash, document, archived_at)
			SELECT 'expired-app-' || n, 'synthetic', 'suspended', 2, '', '{}'::jsonb, $1::timestamptz
			FROM generate_series(1, 100) AS n
			UNION ALL SELECT 'archived-parent', 'synthetic', 'suspended', 2, '', '{}', $1
			UNION ALL SELECT 'active-parent', 'synthetic', 'active', 1, '', '{}', NULL`},
		{"grants", `
			INSERT INTO open_platform.grants (id, app_id, owner_key, app_revision, state, expires_at, document)
			SELECT 'grant-' || n, 'archived-parent', 'synthetic-' || n, 1, 'revoked', $1, '{}'
			FROM generate_series(1, 101) AS n`},
		{"tokens", `
			INSERT INTO open_platform.tokens (hash, grant_id, expires_at, document)
			SELECT 'token-' || n, 'grant-' || n, $1, '{}' FROM generate_series(1, 101) AS n`},
		{"consents", `
			INSERT INTO open_platform.consents (id, owner_key, app_id, expires_at, document)
			SELECT 'consent-' || n, 'synthetic', 'active-parent', $1, '{}' FROM generate_series(1, 101) AS n`},
		{"notices", `
			INSERT INTO open_platform.notices (id, app_id, created_at, document)
			SELECT 'notice-' || n, 'active-parent', $1, '{}' FROM generate_series(1, 101) AS n`},
		{"quotas", `
			INSERT INTO open_platform.quotas (app_id, day, used)
			SELECT 'active-parent', to_char($1::date + n, 'YYYY-MM-DD'), 1 FROM generate_series(1, 101) AS n`},
		{"requests", `
			INSERT INTO open_platform.requests (actor, key, digest, result, created_at)
			SELECT 'synthetic', 'request-' || n, 'digest', '{}', $1 FROM generate_series(1, 101) AS n`},
		{"events", `
			INSERT INTO open_platform.events (actor, kind, object_id, operation, created_at)
			SELECT 'synthetic', 'event', 'object-' || n, 'operation', $1 FROM generate_series(1, 101) AS n`},
		{"invalid_revisions", `
			INSERT INTO open_platform.invalid_revisions (app_id, revision, invalidated_at)
			VALUES ('expired-app-1', 1, $1)`},
	} {
		if _, err := x.db.Exec(seed.query, expired); err != nil {
			t.Fatalf("seed %s: %v", seed.table, err)
		}
	}

	for _, want := range []struct{ removed, remaining int }{{800, 1}, {8, 0}, {0, 0}} {
		removed, err := x.s.Cleanup(ctx, 100)
		if err != nil || removed != want.removed {
			t.Fatalf("cleanup removed %d rows, want %d: %v", removed, want.removed, err)
		}
		for _, table := range []string{"grants", "tokens", "consents", "notices", "quotas", "requests", "events"} {
			if remaining := count(t, x.db, `SELECT count(*) FROM open_platform.`+table); remaining != want.remaining {
				t.Fatalf("%s has %d rows, want %d", table, remaining, want.remaining)
			}
		}
		if remaining := count(t, x.db, `SELECT count(*) FROM open_platform.apps WHERE archived_at IS NOT NULL`); remaining != want.remaining {
			t.Fatalf("archived apps has %d rows, want %d", remaining, want.remaining)
		}
		if remaining := count(t, x.db, `SELECT count(*) FROM open_platform.apps WHERE id = 'active-parent'`); remaining != 1 {
			t.Fatal("cleanup removed the active app")
		}
		if remaining := count(t, x.db, `SELECT count(*) FROM open_platform.invalid_revisions`); remaining != 0 {
			t.Fatal("cleanup retained the deleted app's revision marker")
		}
	}
}
