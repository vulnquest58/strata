package pipeline

import (
	"context"
	"sync"

	"aperture/internal/sources"
)

// Deduplicator tracks seen asset IDs within a pipeline run to suppress duplicates.
// When a second (or later) source reports the same asset, it increments the
// consensus_count in the store instead of emitting a new candidate.
type Deduplicator struct {
	mu   sync.Mutex
	seen map[string]bool // assetID → already emitted
}

// NewDeduplicator creates a fresh deduplication tracker for a single scan.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{seen: make(map[string]bool)}
}

// Filter consumes the input channel and emits only the first occurrence of each assetID.
// Subsequent occurrences still trigger a callback (onDuplicate) so the caller can
// increment consensus counts.
func (d *Deduplicator) Filter(
	ctx context.Context,
	in <-chan sources.RawCandidate,
	onDuplicate func(assetID string),
) <-chan sources.RawCandidate {
	out := make(chan sources.RawCandidate, 256)

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case cand, ok := <-in:
				if !ok {
					return
				}
				if cand.Error != nil || cand.AssetID == "" {
					// Pass errors through so the pipeline can log them.
					select {
					case out <- cand:
					case <-ctx.Done():
						return
					}
					continue
				}

				d.mu.Lock()
				alreadySeen := d.seen[cand.AssetID]
				if !alreadySeen {
					d.seen[cand.AssetID] = true
				}
				d.mu.Unlock()

				if alreadySeen {
					if onDuplicate != nil {
						onDuplicate(cand.AssetID)
					}
				} else {
					select {
					case out <- cand:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return out
}
