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
