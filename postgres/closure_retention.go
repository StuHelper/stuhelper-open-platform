package postgres

import (
	"context"
	"time"
)

// RecordClosureCompletion receives the durable completion fact from the host.
func (r *Repository) RecordClosureCompletion(ctx context.Context, owner, id string, at time.Time) error {
	_, err := r.DB.ExecContext(ctx, "SELECT open_platform.mark_closure_completed($1,$2,$3)", owner, id, at)
	return err
}
func (r *Repository) PruneClosureMarkers(ctx context.Context, limit int) (int64, error) {
	var n int64
	err := r.DB.QueryRowContext(ctx, "SELECT open_platform.prune_closure_markers($1)", limit).Scan(&n)
	return n, err
}
