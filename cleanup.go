package openplatform

import (
	"context"
	"time"
)

// Cleanup caps each data category independently so one backlog cannot starve others.
// At most six times limit rows are removed, with a five-second operation budget.
func (s *Service) Cleanup(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 100 {
		return 0, ErrInput
	}
	repo, ok := s.Repo.(interface {
		Cleanup(context.Context, time.Time, int) (int, error)
	})
	if !ok {
		return 0, ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return repo.Cleanup(call, s.now(), limit)
}

// Backlog inspects pending termination notices and retention cleanup lag within a five-second budget.
func (s *Service) Backlog(ctx context.Context) (BacklogSummary, error) {
	if s.Repo == nil {
		return BacklogSummary{}, ErrUnavailable
	}
	repo, ok := s.Repo.(interface {
		Backlog(context.Context, time.Time) (BacklogSummary, error)
	})
	if !ok {
		return BacklogSummary{}, ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return repo.Backlog(call, s.now())
}
