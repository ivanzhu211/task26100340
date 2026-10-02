package topip

import (
	"net/netip"
	"sort"
	"testing"
)

type attackerSpec struct {
	ip         netip.Addr
	start, end int // active minutes [start, end)
	rate       int // base records per minute
}

// t50Of returns the 50th largest true count given the attacker true
// counts and the number of one-off flood addresses (each counting 1).
func t50Of(trueA []uint64, floodOnes int64) uint64 {
	s := make([]uint64, len(trueA))
	copy(s, trueA)
	sort.Slice(s, func(i, j int) bool { return s[i] > s[j] })
	rank := int64(0)
	ones := floodOnes
	for _, v := range s {
		if v <= 1 {
			if v == 1 {
				ones++
			}
			continue
		}
		rank++
		if rank == 50 {
			return v
		}
	}
	if rank+ones >= 50 {
		return 1
	}
	return 0
}

// TestFloodAccuracy replays a DDoS-like flood: millions of one-off
// spoofed addresses over 26 hours, hiding a few dozen persistent
// attackers of varying strength and activity windows. It then checks
// the three deterministic guarantees against exact counts at several
// query times.
func TestFloodAccuracy(t *testing.T) {
	const (
		spanMin    = 1560 // 26 hours
		m0         = int64(3_000_000)
		floodTotal = 7_500_000
	)
	specs := make([]attackerSpec, 0, 65)
	addSpec := func(start, end, rate int) {
		a := len(specs)
		specs = append(specs, attackerSpec{
			ip:    v4(10, 255, byte(a>>8), byte(a)),
			start: start, end: end, rate: rate,
		})
	}
	for i := 0; i < 10; i++ { // strong, active the whole time
		addSpec(0, spanMin, 80)
	}
	for i := 0; i < 20; i++ { // medium
		addSpec(200, 1400, 30)
	}
	for i := 0; i < 20; i++ { // weak
		addSpec(400, 1000, 8)
	}
	for i := 0; i < 15; i++ { // burst, only early hours
		addSpec(50, 150, 150)
	}

	attackerMin := make([][]uint32, len(specs))
	for i := range attackerMin {
		attackerMin[i] = make([]uint32, spanMin)
	}
	floodPerMin := make([]uint32, spanMin)
	for m := 0; m < spanMin; m++ {
		floodPerMin[m] = floodTotal / spanMin
		if m < floodTotal%spanMin {
			floodPerMin[m]++
		}
	}

	tr := NewTracker()
	var floodC uint32
	feed := func(m int) {
		base := (m0 + int64(m)) * 60
		for j := uint32(0); j < floodPerMin[m]; j++ {
			floodC++
			tr.Record(noiseIP(uint16(m), floodC), base+int64(j%60))
		}
		for a, sp := range specs {
			if m < sp.start || m >= sp.end {
				continue
			}
			c := sp.rate + (a*7+m*13)%(sp.rate/2+1)
			attackerMin[a][m] = uint32(c)
			for j := 0; j < c; j++ {
				tr.Record(sp.ip, base+int64(j%60))
			}
		}
	}

	check := func(w int) {
		now := (m0+int64(w))*60 + 30
		lo := w - (windowMinutes - 1)
		if lo < 0 {
			lo = 0
		}
		hi := w - 1 // minutes < w have been fed; minute w has no records yet
		if hi > spanMin-1 {
			hi = spanMin - 1
		}
		trueA := make([]uint64, len(specs))
		var n, floodOnes int64
		for m := lo; m <= hi; m++ {
			floodOnes += int64(floodPerMin[m])
			for a := range specs {
				trueA[a] += uint64(attackerMin[a][m])
			}
		}
		n = floodOnes
		for a := range specs {
			n += int64(trueA[a])
		}
		t50 := t50Of(trueA, floodOnes)

		trueOf := func(ip netip.Addr) uint64 {
			b := ip.As16()
			if b[0] == 0x20 && b[1] == 0x01 { // flood address
				if off := int(noiseMinuteOff(ip)); off >= lo && off <= hi {
					return 1
				}
				return 0
			}
			return trueA[int(b[14])<<8|int(b[15])]
		}

		items := tr.Top(now)
		if len(items) > topK {
			t.Fatalf("w=%d: Top returned %d items, want <= %d", w, len(items), topK)
		}
		if n == 0 {
			if len(items) != 0 {
				t.Fatalf("w=%d: empty window but Top returned %d items", w, len(items))
			}
			return
		}
		errBound := float64(n) / 1000
		mustBeat := float64(t50) + float64(n)/500
		floor := int64(t50) - int64(n)/500

		inRes := make(map[[16]byte]bool, len(items))
		for _, it := range items {
			k := it.IP.As16()
			inRes[k] = true
			tc := trueOf(it.IP)
			d := float64(it.Count) - float64(tc)
			if d < 0 {
				d = -d
			}
			if d > errBound {
				t.Errorf("w=%d: %v count %d vs true %d exceeds N/1000=%.0f",
					w, it.IP, it.Count, tc, errBound)
			}
			if int64(tc) < floor {
				t.Errorf("w=%d: %v true count %d below t50-N/500=%d", w, it.IP, tc, floor)
			}
		}
		for a, sp := range specs {
			if float64(trueA[a]) > mustBeat && !inRes[sp.ip.As16()] {
				t.Errorf("w=%d: attacker %d (true %d > %.0f) missing from Top",
					w, a, trueA[a], mustBeat)
			}
		}
		// Attackers whose every minute expired from the window must be
		// gone entirely (exact minute-granularity expiry).
		for a, sp := range specs {
			if trueA[a] == 0 && inRes[sp.ip.As16()] {
				t.Errorf("w=%d: expired attacker %d still in Top", w, a)
			}
		}
		var topCount uint64
		if len(items) > 0 {
			topCount = items[0].Count
		}
		t.Logf("w=%d: N=%d t50=%d items=%d top=%d", w, n, t50, len(items), topCount)
	}

	stage := 0
	for _, w := range []int{800, 1500, 1559, 2059, 2999} {
		for ; stage < spanMin && stage < w; stage++ {
			feed(stage)
		}
		check(w)
	}
}
