// Package topk implements an in-memory heavy-hitter tracker for an edge
// security gateway dashboard: the top 50 blocked source IPs over a sliding
// 24-hour window with minute-exact boundaries.
//
// Design: each minute keeps a Space-Saving summary of capacity minuteCap
// (deterministic error <= N_minute/minuteCap). A global merged hash table
// maintains the sum of all live minute summaries, so a window estimate is
// off by at most sum(N_i)/minuteCap = N/1000, which satisfies the required
// guarantees deterministically for every input sequence.
package topk

import (
	"net/netip"
	"sync"
)

// TopEntry is one row of the Top result: an IP and its estimated block
// count inside the current window.
type TopEntry struct {
	IP    netip.Addr
	Count uint64
}

// Tracker counts blocked requests and answers top-50 queries over the last
// 1440 minutes. The zero value is not usable; call New.
//
// Memory usage is bounded by a constant independent of the number of
// distinct source IPs seen.
type Tracker struct {
	mu        sync.Mutex
	table     ipTable
	ring      [ringSize]minuteBuf
	maxMinute int64 // minute index of the largest ts ever recorded; -1 when empty
	loMinute  int64 // minutes < loMinute have been expired from table
}

// New returns an empty Tracker.
func New() *Tracker {
	t := &Tracker{maxMinute: -1, loMinute: 0}
	t.table.init()
	for i := range t.ring {
		t.ring[i].min = -1
	}
	return t
}

// Record notes one blocked request from ip at time ts (Unix seconds).
// Safe for concurrent use.
//
// ts may be up to 2 minutes smaller than the largest ts seen so far; such
// late records are still counted into their own minute. Records older than
// that are dropped.
func (t *Tracker) Record(ip netip.Addr, ts int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record(ip.As16(), ts)
}

// Top returns up to 50 IPs with the highest estimated block counts in the
// window covering the minute of now (Unix seconds) and the 1439 full
// minutes before it, sorted by count descending. now must be monotonic
// non-decreasing across calls and no smaller than any recorded ts.
func (t *Tracker) Top(now int64) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.top(now)
}
