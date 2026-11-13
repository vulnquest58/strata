package utils

import (
	"math"
	"math/rand"
	"time"
)

// Jitter provides adaptive, randomized delays to reduce detection fingerprint.
type Jitter struct {
	BaseDelay    time.Duration
	JitterFactor float64 // multiplier for random jitter range
	StealthMode  bool
}

// NewJitter creates a Jitter controller.
// In stealth mode, base delay is tripled and jitter factor doubled.
func NewJitter(baseMsec int, jitterFactor float64, stealth bool) *Jitter {
	base := time.Duration(baseMsec) * time.Millisecond
	if stealth {
		base = base * 3
		jitterFactor = jitterFactor * 2
	}
	return &Jitter{
		BaseDelay:    base,
		JitterFactor: jitterFactor,
		StealthMode:  stealth,
	}
}

// Sleep blocks for base delay + random jitter.
func (j *Jitter) Sleep() {
	jitterMs := int(float64(j.BaseDelay.Milliseconds()) * j.JitterFactor)
	if jitterMs < 1 {
		jitterMs = 1
	}
	extra := time.Duration(rand.Intn(jitterMs)) * time.Millisecond
	time.Sleep(j.BaseDelay + extra)
}

// SleepShort applies a minimal jitter sleep for non-stealth contexts.
func SleepShort() {
	time.Sleep(time.Duration(50+rand.Intn(150)) * time.Millisecond)
}

// SleepBetween sleeps a random duration between min and max milliseconds.
func SleepBetween(minMs, maxMs int) {
	if maxMs <= minMs {
		maxMs = minMs + 100
	}
	d := time.Duration(minMs+rand.Intn(maxMs-minMs)) * time.Millisecond
	time.Sleep(d)
}

// RetryWithBackoff retries fn up to maxRetries times using exponential backoff.
// baseMs is the initial delay in milliseconds. Returns the last error on failure.
func RetryWithBackoff(maxRetries int, baseMs int, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if attempt < maxRetries-1 {
			// base * 2^attempt + random jitter, capped at 15s
			delay := time.Duration(float64(baseMs)*math.Pow(2, float64(attempt))) * time.Millisecond
			jitter := time.Duration(rand.Intn(baseMs+1)) * time.Millisecond
			total := delay + jitter
			if total > 15*time.Second {
				total = 15 * time.Second
			}
			time.Sleep(total)
		}
	}
	return lastErr
}
