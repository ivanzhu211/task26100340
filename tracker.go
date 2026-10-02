package topk

import "net/netip"

// windowMinutes is the exact window length: the minute of now plus the
// 1439 full minutes before it.
const windowMinutes = 1440

// lateGraceMinutes is how far behind the largest seen ts a record may lag
// and still be counted into its own minute.
const lateGraceMinutes = 2

// topK is the maximum number of entries returned by Top.
const topK = 50

// secondsPerMinute converts Unix seconds to minute indices.
const secondsPerMinute = 60

// record is the unlocked body of Record.
func (t *Tracker) record(ip [16]byte, ts int64) {
	m := ts / secondsPerMinute
	if t.maxMinute < 0 {
		t.advance(m)
	} else {
		if m < t.maxMinute-lateGraceMinutes {
			return // arrived too late; allowed to drop
		}
		if m > t.maxMinute {
			t.advance(m)
		}
	}
	buf := &t.ring[m&(ringSize-1)]
	if buf.min != m {
		// The buffer's previous occupant (minute m-ringSize) is long
		// expired: ringSize exceeds the maximum number of live minutes.
		buf.activate(m)
	}
	evicted := buf.add(ip)
	if evicted == nil {
		t.table.add(ip, 1)
	} else {
		t.table.sub(evicted.ip, uint64(evicted.cnt))
		t.table.add(ip, uint64(evicted.cnt)+1)
	}
}

// advance moves the current minute forward to m, sealing minutes that fall
// out of the late-arrival grace period and expiring minutes that fall out
// of the window.
func (t *Tracker) advance(m int64) {
	old := t.maxMinute
	if old >= 0 {
		for mm := old - lateGraceMinutes; mm <= old; mm++ {
			if mm < m-lateGraceMinutes {
				buf := &t.ring[mm&(ringSize-1)]
				if buf.min == mm {
					buf.seal()
				}
			}
		}
	}
	t.maxMinute = m
	t.expireTo(m - (windowMinutes - 1))
}

// expireTo removes every minute < lo from the merged table. lo must be
// monotonic non-decreasing across calls.
func (t *Tracker) expireTo(lo int64) {
	if lo <= t.loMinute {
		return
	}
	if t.maxMinute < lo {
		// Every live minute expired at once: bulk clear.
		t.table.clear()
		for i := range t.ring {
			if t.ring[i].min >= 0 && t.ring[i].min < lo {
				t.ring[i].reset(-1)
			}
		}
		t.loMinute = lo
		return
	}
	for mm := t.loMinute; mm < lo; mm++ {
		buf := &t.ring[mm&(ringSize-1)]
		if buf.min != mm {
			continue
		}
		for j := int32(0); j < buf.n; j++ {
			e := &buf.entries[j]
			t.table.sub(e.ip, uint64(e.cnt))
		}
		buf.reset(-1)
	}
	t.loMinute = lo
}

// top is the unlocked body of Top.
func (t *Tracker) top(now int64) []TopEntry {
	if t.maxMinute < 0 {
		return nil
	}
	t.expireTo(now/secondsPerMinute - (windowMinutes - 1))

	var sel [topK]TopEntry
	n := 0
	for i, v := range t.table.vals {
		if v == 0 {
			continue
		}
		if n == topK && !ranksAbove(t.table.keys[i], v, sel[n-1]) {
			continue
		}
		// Insertion into the (tiny) sorted selection, ordered by count
		// descending, ties broken by IP bytes for determinism.
		e := TopEntry{IP: netip.AddrFrom16(t.table.keys[i]).Unmap(), Count: v}
		pos := n
		if pos == topK {
			pos--
		}
		for pos > 0 && ranksAbove(t.table.keys[i], v, sel[pos-1]) {
			sel[pos] = sel[pos-1]
			pos--
		}
		sel[pos] = e
		if n < topK {
			n++
		}
	}
	return sel[:n]
}

// ranksAbove reports whether the candidate (ip, cnt) ranks strictly above
// e in the result ordering (count descending, IP bytes ascending).
func ranksAbove(ip [16]byte, cnt uint64, e TopEntry) bool {
	if cnt != e.Count {
		return cnt > e.Count
	}
	cur := e.IP.As16()
	return string(ip[:]) < string(cur[:])
}
