package topk

import (
	"math/rand"
	"net/netip"
	"testing"
)

// floodRef keeps an exact reference for the flood test. Random flood IPs
// are generated unique (true count exactly 1), so only the attacker IPs
// need exact per-minute bookkeeping.
type floodRef struct {
	atkWin   map[[16]byte]int64 // exact in-window counts of attacker IPs
	perMin   []map[[16]byte]int64
	randMin  []int64 // random (count-1) records per minute
	totMin   []int64 // total records per minute
	applied  int     // minutes added to the window so far
	expired  int     // minutes removed from the window so far
	randWin  int64   // random records currently in the window
	N        int64   // total records currently in the window
	startMin int64
}

// syncTo applies all generated minutes up to nowMin and expires everything
// before the window [nowMin-1439, nowMin].
func (r *floodRef) syncTo(nowMin int64) {
	for r.applied < len(r.perMin) && r.startMin+int64(r.applied) <= nowMin {
		m := r.applied
		r.applied++
		r.N += r.totMin[m]
		r.randWin += r.randMin[m]
		for ip, c := range r.perMin[m] {
			r.atkWin[ip] += c
		}
	}
	lo := nowMin - (windowMinutes - 1)
	for r.expired < r.applied && r.startMin+int64(r.expired) < lo {
		m := r.expired
		r.expired++
		r.N -= r.totMin[m]
		r.randWin -= r.randMin[m]
		for ip, c := range r.perMin[m] {
			r.atkWin[ip] -= c
			if r.atkWin[ip] == 0 {
				delete(r.atkWin, ip)
			}
		}
	}
}

// TestFlood simulates a DDoS: >10M blocks over 25 hours, mostly one-shot
// random source IPs, with 80 attackers of varying intensity and schedules
// mixed in. At many checkpoints it verifies all three guarantees against
// exact counts.
func TestFlood(t *testing.T) {
	tr := New()
	rng := rand.New(rand.NewSource(7))

	const minutes = 1500 // 25 hours
	const numAtk = 80
	const randPerMin = 5000
	startMin := int64(5_000_000)

	atkIPs := make([]netip.Addr, numAtk)
	for i := range atkIPs {
		atkIPs[i] = mustIP("10.1." + itoa(i/256) + "." + itoa(i%256))
	}
	atkRate := make([]int, numAtk)
	for i := range atkRate {
		atkRate[i] = 20 + (i*37)%400
		if i%10 == 0 {
			atkRate[i] += 800
		}
	}
	atkActive := func(i, m int) bool {
		if i < 6 {
			return true
		}
		return (m/60+i)%4 != 0 // active 3 out of 4 hours, staggered
	}

	ref := &floodRef{
		atkWin:   make(map[[16]byte]int64),
		startMin: startMin,
	}

	var randCounter uint64
	nextRandIP := func() netip.Addr {
		var b [16]byte
		randCounter++
		b[0] = 0x20 // global unicast space, disjoint from mapped IPv4
		for k := 0; k < 8; k++ {
			b[8+k] = byte(randCounter >> (8 * k))
		}
		b[7] = byte(rng.Intn(256))
		return netip.AddrFrom16(b)
	}

	checkpoints := 0
	for mi := 0; mi < minutes; mi++ {
		m := startMin + int64(mi)
		minuteAtk := make(map[[16]byte]int64)
		var minuteTot int64

		// Attacker traffic for this minute.
		for i := 0; i < numAtk; i++ {
			if !atkActive(i, mi) {
				continue
			}
			rate := atkRate[i] + rng.Intn(50)
			ip16 := atkIPs[i].As16()
			for j := 0; j < rate; j++ {
				tr.Record(atkIPs[i], m*60+int64(rng.Intn(60)))
			}
			minuteAtk[ip16] += int64(rate)
			minuteTot += int64(rate)
		}
		// Random one-shot flood traffic.
		for j := 0; j < randPerMin; j++ {
			tr.Record(nextRandIP(), m*60+int64(rng.Intn(60)))
		}
		minuteTot += randPerMin

		ref.perMin = append(ref.perMin, minuteAtk)
		ref.randMin = append(ref.randMin, randPerMin)
		ref.totMin = append(ref.totMin, minuteTot)

		// Checkpoint roughly every hour once the window is busy, at
		// different sub-minute offsets.
		if mi >= 120 && mi%60 == 0 {
			now := m*60 + 59
			verifyGuarantees(t, tr, now, ref)
			checkpoints++
			// Also check with `now` inside the next minute (no records
			// there yet), exercising window sliding without new data.
			if mi%120 == 0 {
				verifyGuarantees(t, tr, now+61, ref)
			}
		}
	}
	if checkpoints < 20 {
		t.Fatalf("only %d checkpoints", checkpoints)
	}
}

func verifyGuarantees(t *testing.T, tr *Tracker, now int64, ref *floodRef) {
	t.Helper()
	ref.syncTo(now / 60)

	top := tr.Top(now)
	if len(top) > topK {
		t.Fatalf("now=%d: Top returned %d entries", now, len(top))
	}
	for i := 1; i < len(top); i++ {
		if top[i-1].Count < top[i].Count {
			t.Fatalf("now=%d: Top not sorted descending", now)
		}
	}

	trueCount := func(ip netip.Addr) int64 {
		if c, ok := ref.atkWin[ip.As16()]; ok {
			return c
		}
		return 1 // random flood IP, unique by construction
	}

	// t50: 50th largest true count in the window.
	counts := make([]int64, 0, len(ref.atkWin))
	for _, c := range ref.atkWin {
		counts = append(counts, c)
	}
	for i := 0; i < len(counts); i++ { // sort descending (<= 80 elements)
		for j := i + 1; j < len(counts); j++ {
			if counts[j] > counts[i] {
				counts[i], counts[j] = counts[j], counts[i]
			}
		}
	}
	var t50 int64
	if len(counts) >= topK {
		t50 = counts[topK-1]
	} else if ref.randWin > 0 {
		t50 = 1
	}

	N := ref.N
	// Guarantee 1: every returned count within N/1000 of the true count.
	for _, e := range top {
		tru := trueCount(e.IP)
		d := int64(e.Count) - tru
		if d < 0 {
			d = -d
		}
		if d > N/1000 {
			t.Errorf("now=%d: ip=%v est=%d true=%d exceeds N/1000=%d",
				now, e.IP, e.Count, tru, N/1000)
		}
	}
	// Guarantee 2: every IP with true > t50+N/500 must appear.
	present := make(map[netip.Addr]bool, len(top))
	for _, e := range top {
		present[e.IP] = true
	}
	for ip16, c := range ref.atkWin {
		if c > t50+N/500 {
			ip := netip.AddrFrom16(ip16).Unmap()
			if !present[ip] {
				t.Errorf("now=%d: heavy hitter %v true=%d > t50+N/500=%d missing",
					now, ip, c, t50+N/500)
			}
		}
	}
	// Guarantee 3: every returned IP has true >= t50-N/500.
	for _, e := range top {
		if tru := trueCount(e.IP); tru < t50-N/500 {
			t.Errorf("now=%d: ip=%v true=%d < t50-N/500=%d",
				now, e.IP, tru, t50-N/500)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
