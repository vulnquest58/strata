package passive

import (
	"context"
	"sync"
	"time"
)

// RateLimiter manages inter-request pacing proactively for external API plugins.
type RateLimiter struct {
	minInterval time.Duration
	lastRequest time.Time
	mu          sync.Mutex
}

// NewRateLimiter creates a RateLimiter with the given minimum duration between requests.
func NewRateLimiter(minInterval time.Duration) *RateLimiter {
	return &RateLimiter{
		minInterval: minInterval,
	}
}

// Throttle blocks until the minimum interval since the last request has elapsed,
// or until the context is cancelled.
func (r *RateLimiter) Throttle(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	elapsed := time.Since(r.lastRequest)
	if elapsed < r.minInterval && !r.lastRequest.IsZero() {
		wait := r.minInterval - elapsed
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	r.lastRequest = time.Now()
	return nil
}
