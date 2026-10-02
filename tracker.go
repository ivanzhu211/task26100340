// Package topip implements an in-memory sliding-window heavy-hitter
// tracker for blocked source IPs. It reports the top source IPs by
// block count over the last 1440 minutes (the minute containing `now`
// plus the 1439 full minutes before it).
//
// The structure is a ring of per-minute Space-Saving summaries plus a
// globally maintained aggregate of per-IP estimated counts. All
// guarantees are deterministic (no sampling, no randomization).
package topip

import (
	"bytes"
	"net/netip"
	"sort"
	"sync"
)

const (
	// windowMinutes is the exact sliding window length in minutes.
	windowMinutes = 1440
	// ringSize is the number of minute slots in the ring; must be a
	// power of two >= windowMinutes.
	ringSize = 2048
	ringMask = ringSize - 1
	// topK is the maximum number of IPs returned by Top.
	topK = 50
)

// Item is one entry of a Top result: an IP and its estimated block
// count inside the current window.
type Item struct {
	IP    netip.Addr
	Count uint64
}

// Tracker records blocked requests and answers top-IP queries.
// The zero value is not usable; use NewTracker. All methods are safe
// for concurrent use.
type Tracker struct {
	mu      sync.Mutex
	slots   [ringSize]*minuteSlot
	agg     aggTable
	curMin  int64 // greatest minute index seen in any Record
	aggFrom int64 // oldest minute index still present in agg
	started bool
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker {
	t := &Tracker{}
	t.agg.init()
	return t
}

// Record notes one blocked request from ip at time ts (unix seconds).
//
// ts may be up to 2 minutes behind the greatest timestamp seen so far;
// such late records are still counted in the minute they belong to.
// Records whose minute has already fallen out of the window are
// dropped, which the contract permits for anything later than that.
func (t *Tracker) Record(ip netip.Addr, ts int64) {
	key := ip.As16()
	m := minuteOf(ts)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started {
		t.started = true
		t.curMin = m
		t.aggFrom = m - (windowMinutes - 1)
	}
	if m > t.curMin {
		t.advanceLocked(m)
	}
	if m < t.aggFrom {
		// The minute this record belongs to has already expired from
		// the window; counting it could never affect any future Top.
		return
	}
	// Invariant: every live slot holds a minute in [aggFrom, curMin],
	// a span of at most windowMinutes < ringSize minutes, so the slot
	// for m is either nil or already the slot of minute m.
	idx := m & ringMask
	s := t.slots[idx]
	if s == nil {
		s = newMinuteSlot(m)
		t.slots[idx] = s
	}
	s.add(key, &t.agg)
}

// Top returns the at most 50 IPs with the highest estimated block
// counts in the window [minute(now)-1439, minute(now)], sorted by
// count descending.
//
// now is monotonically non-decreasing across calls and never smaller
// than any recorded ts.
func (t *Tracker) Top(now int64) []Item {
	m := minuteOf(now)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		if from := m - (windowMinutes - 1); from > t.aggFrom {
			t.expireBeforeLocked(from)
		}
	}
	top := t.topLocked()
	sort.Slice(top, func(i, j int) bool {
		if top[i].count != top[j].count {
			return top[i].count > top[j].count
		}
		return bytes.Compare(top[i].key[:], top[j].key[:]) < 0
	})
	items := make([]Item, len(top))
	for i, it := range top {
		items[i] = Item{IP: netip.AddrFrom16(it.key).Unmap(), Count: it.count}
	}
	return items
}

// topLocked collects the topK aggregate entries by count.
// Caller holds the lock.
//
// Phase 1 finds T, the 50th largest per-block maximum; any block whose
// maximum is below T holds no top-50 candidate, so phase 2 only scans
// blocks with blockMax >= T (and blocks that are not completely empty).
func (t *Tracker) topLocked() []topItem {
	var bh [topK]uint64
	bn := 0
	for _, m := range t.agg.blockMax {
		if m == 0 {
			continue
		}
		if bn < topK {
			bh[bn] = m
			bn++
			for i := bn - 1; i > 0 && bh[i] < bh[(i-1)/2]; i = (i - 1) / 2 {
				bh[i], bh[(i-1)/2] = bh[(i-1)/2], bh[i]
			}
		} else if m > bh[0] {
			bh[0] = m
			for i := 0; ; {
				l := 2*i + 1
				if l >= topK {
					break
				}
				s := l
				if r := l + 1; r < topK && bh[r] < bh[l] {
					s = r
				}
				if bh[s] >= bh[i] {
					break
				}
				bh[s], bh[i] = bh[i], bh[s]
				i = s
			}
		}
	}
	var threshold uint64
	if bn == topK {
		threshold = bh[0]
	}
	if threshold < 1 {
		threshold = 1
	}
	top := make([]topItem, 0, topK)
	counts := t.agg.counts
	keys := t.agg.keys
	for b, m := range t.agg.blockMax {
		if m < threshold {
			continue
		}
		base := b << aggBlockShift
		for i := base; i < base+aggBlockSize; i++ {
			c := counts[i]
			if c == 0 {
				continue
			}
			if len(top) == topK && c < top[0].count {
				continue
			}
			it := topItem{key: keys[i], count: c}
			if len(top) < topK {
				top = append(top, it)
				topSiftUp(top, len(top)-1)
			} else if topLess(top[0], it) {
				top[0] = it
				topSiftDown(top, 0)
			}
		}
	}
	return top
}

// advanceLocked moves curMin forward to m, expiring every minute that
// falls out of the window [m-1439, m]. Caller holds the lock.
func (t *Tracker) advanceLocked(m int64) {
	t.expireBeforeLocked(m - (windowMinutes - 1))
	t.curMin = m
}

// expireBeforeLocked drops all live slots with minute < from from the
// ring and from the aggregate, and raises aggFrom to from.
// Caller holds the lock.
func (t *Tracker) expireBeforeLocked(from int64) {
	if from <= t.aggFrom {
		return
	}
	for mm := t.aggFrom; mm < from; mm++ {
		idx := mm & ringMask
		s := t.slots[idx]
		if s == nil || s.minute != mm {
			continue
		}
		for _, e := range s.entries[:s.n] {
			t.agg.sub(e.key, e.count)
		}
		t.slots[idx] = nil
	}
	t.aggFrom = from
}

// topItem is a candidate for the Top result set.
type topItem struct {
	key   [16]byte
	count uint64
}

// topLess orders the min-heap of candidates: the "smallest" element
// (the first to be replaced) is the one with the lowest count, ties
// broken by greater key so that the final selection is deterministic.
func topLess(a, b topItem) bool {
	if a.count != b.count {
		return a.count < b.count
	}
	return bytes.Compare(a.key[:], b.key[:]) > 0
}

func topSiftUp(h []topItem, i int) {
	for i > 0 {
		p := (i - 1) / 2
		if !topLess(h[i], h[p]) {
			return
		}
		h[i], h[p] = h[p], h[i]
		i = p
	}
}

func topSiftDown(h []topItem, i int) {
	n := len(h)
	for {
		l := 2*i + 1
		if l >= n {
			return
		}
		m := l
		if r := l + 1; r < n && topLess(h[r], h[l]) {
			m = r
		}
		if !topLess(h[m], h[i]) {
			return
		}
		h[m], h[i] = h[i], h[m]
		i = m
	}
}

// minuteOf returns the minute index containing unix timestamp ts
// (floor division, correct for negative ts as well).
func minuteOf(ts int64) int64 {
	if ts >= 0 {
		return ts / 60
	}
	return -((-ts + 59) / 60)
}
