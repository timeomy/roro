package policy

import (
	"sync"
	"time"
)

// RateWindow is the window rate counters cover.
const RateWindow = time.Minute

// maxTracked bounds memory per key; counts saturate at this value.
const maxTracked = 10000

// RateCounter counts tool-call attempts per agent and per agent+tool over a
// sliding one-minute window. It only counts; Cedar policies compare the
// counts to limits (context.rate.*).
//
// Counters live in process memory. Each Roro process counts its own
// traffic; see docs/policy.md.
type RateCounter struct {
	mu        sync.Mutex
	events    map[string][]time.Time
	lastSweep time.Time
}

// NewRateCounter returns an empty counter.
func NewRateCounter() *RateCounter {
	return &RateCounter{events: map[string][]time.Time{}}
}

// Record registers one attempt at now and returns the counts in the window
// ending at now, including this attempt.
func (c *RateCounter) Record(agent, tool string, now time.Time) (agentCount, toolCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweep(now)
	agentCount = c.add("a\x00"+agent, now)
	toolCount = c.add("t\x00"+agent+"\x00"+tool, now)
	return agentCount, toolCount
}

// sweep drops keys with no events in the window, at most once per window,
// so keys for tool names an agent made up do not accumulate.
func (c *RateCounter) sweep(now time.Time) {
	if now.Sub(c.lastSweep) < RateWindow {
		return
	}
	c.lastSweep = now
	cutoff := now.Add(-RateWindow)
	for k, ts := range c.events {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(c.events, k)
		}
	}
}

// keys reports how many keys are tracked (for tests).
func (c *RateCounter) keys() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *RateCounter) add(key string, now time.Time) int {
	cutoff := now.Add(-RateWindow)
	old := c.events[key]
	kept := make([]time.Time, 0, len(old)+1)
	for _, t := range old {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) < maxTracked {
		kept = append(kept, now)
	}
	c.events[key] = kept
	return len(kept)
}
