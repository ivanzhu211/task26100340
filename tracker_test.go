package topip

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"
)

func v4(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// noiseIP builds a unique IPv6 address embedding a minute offset and a
// counter, so tests can decode which minute the address belonged to.
func noiseIP(minuteOff uint16, c uint32) netip.Addr {
	var b [16]byte
	b[0] = 0x20
	b[1] = 0x01
	binary.BigEndian.PutUint16(b[2:4], minuteOff)
	binary.BigEndian.PutUint32(b[4:8], c)
	return netip.AddrFrom16(b)
}

func noiseMinuteOff(ip netip.Addr) uint16 {
	b := ip.As16()
	return binary.BigEndian.Uint16(b[2:4])
}

func findItem(items []Item, ip netip.Addr) (Item, bool) {
	k := ip.As16()
	for _, it := range items {
		if it.IP.As16() == k {
			return it, true
		}
	}
	return Item{}, false
}

// TestSmoke checks basic exact behavior on a tiny input where no
// eviction ever happens.
func TestSmoke(t *testing.T) {
	tr := NewTracker()
	base := int64(1_700_000_000)
	a := v4(1, 2, 3, 4)
	b := v4(5, 6, 7, 8)
	for i := 0; i < 100; i++ {
		tr.Record(a, base+int64(i%60))
	}
	for i := 0; i < 40; i++ {
		tr.Record(b, base+int64(i%60))
	}
	items := tr.Top(base + 30)
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
	if items[0].IP != a || items[0].Count != 100 {
		t.Fatalf("top item = %+v, want %v x100", items[0], a)
	}
	if items[1].IP != b || items[1].Count != 40 {
		t.Fatalf("second item = %+v, want %v x40", items[1], b)
	}
}

// TestWindowBoundary places the two heaviest hitters in the two
// minutes straddling the window edge: the one in the earliest in-window
// minute must be reported, the one one minute earlier must not.
func TestWindowBoundary(t *testing.T) {
	tr := NewTracker()
	const m0 = int64(1_000_000)
	ts := func(m int64) int64 { return m * 60 }

	ipA := v4(10, 0, 0, 1) // strikes only in the earliest in-window minute
	ipB := v4(10, 0, 0, 2) // strikes only one minute before the window

	for i := 0; i < 200_000; i++ {
		tr.Record(ipB, ts(m0-1)+int64(i%60))
	}
	for i := 0; i < 200_000; i++ {
		tr.Record(ipA, ts(m0)+int64(i%60))
	}
	// 40 medium hitters spread across the rest of the window.
	fillers := make([]netip.Addr, 40)
	for f := 0; f < 40; f++ {
		fillers[f] = v4(10, 1, byte(f/256), byte(f%256))
		for j := 0; j < 5000; j++ {
			m := m0 + 1 + int64(j%1439)
			tr.Record(fillers[f], ts(m)+int64(j%60))
		}
	}
	// One-off noise in every minute of the window.
	var c uint32
	for m := m0; m <= m0+1439; m++ {
		for j := 0; j < 500; j++ {
			c++
			tr.Record(noiseIP(uint16(m-m0), c), ts(m)+int64(j%60))
		}
	}

	now := ts(m0+1439) + 30
	items := tr.Top(now)

	const n = 200_000 + 40*5_000 + 1440*500 // records inside the window
	const errBound = n / 1000

	itA, ok := findItem(items, ipA)
	if !ok {
		t.Fatal("ipA (earliest in-window minute) missing from Top")
	}
	if d := int64(itA.Count) - 200_000; d < 0 || d > errBound {
		t.Fatalf("ipA count %d off by %d, bound %d", itA.Count, d, errBound)
	}
	if _, ok := findItem(items, ipB); ok {
		t.Fatal("ipB (one minute before window) must not appear in Top")
	}
	// t50 = 1 (noise), so every filler with 5000 > 1 + n/500 must appear.
	for _, f := range fillers {
		it, ok := findItem(items, f)
		if !ok {
			t.Fatalf("filler %v missing from Top", f)
		}
		if d := int64(it.Count) - 5_000; d < 0 || d > errBound {
			t.Fatalf("filler %v count %d off by %d, bound %d", f, it.Count, d, errBound)
		}
	}
	// Every returned count must be within n/1000 of the true count.
	for _, it := range items {
		var trueCount int64
		switch k := it.IP.As16(); {
		case k[12] == 10 && k[13] == 0 && k[15] == 1:
			trueCount = 200_000
		case k[12] == 10 && k[13] == 0 && k[15] == 2:
			trueCount = 0
		case k[12] == 10 && k[13] == 1:
			trueCount = 5_000
		default: // noise, one occurrence inside the window
			if off := noiseMinuteOff(it.IP); off <= 1439 {
				trueCount = 1
			}
		}
		if d := int64(it.Count) - trueCount; d < 0 || d > errBound {
			t.Fatalf("item %v count %d vs true %d, bound %d", it.IP, it.Count, trueCount, errBound)
		}
	}
}

// TestLateArrival checks that records arriving 1-2 minutes late are
// counted in the minute they belong to and expire together with it.
func TestLateArrival(t *testing.T) {
	tr := NewTracker()
	const h = int64(1_700_003_600) // exact hour boundary
	m := h / 60

	// Push the max seen timestamp to h+150 (minute m+2).
	for i := 0; i < 100; i++ {
		tr.Record(noiseIP(0, uint32(i+1)), h+150)
	}
	late1m := v4(10, 9, 0, 1) // 60s late, belongs to minute m+1
	late2m := v4(10, 9, 0, 2) // 120s late, belongs to minute m
	for i := 0; i < 4000; i++ {
		tr.Record(late1m, h+90)
	}
	for i := 0; i < 5000; i++ {
		tr.Record(late2m, h+30)
	}

	items := tr.Top(h + 150)
	n := uint64(100 + 4000 + 5000)
	errBound := n / 1000
	it1, ok := findItem(items, late1m)
	if !ok {
		t.Fatal("60s-late records not counted")
	}
	if d := it1.Count - 4000; d > errBound {
		t.Fatalf("late1m count %d off by %d, bound %d", it1.Count, d, errBound)
	}
	it2, ok := findItem(items, late2m)
	if !ok {
		t.Fatal("120s-late records not counted")
	}
	if d := it2.Count - 5000; d > errBound {
		t.Fatalf("late2m count %d off by %d, bound %d", it2.Count, d, errBound)
	}

	// Slide the window so that minute m expires but m+1 stays: the
	// 120s-late hitter must vanish (proving it was booked into minute
	// m, not into its arrival minute), the 60s-late one must remain.
	now := (m+1+1439)*60 + 10
	items = tr.Top(now)
	if _, ok := findItem(items, late2m); ok {
		t.Fatal("late2m must expire together with minute m")
	}
	if _, ok := findItem(items, late1m); !ok {
		t.Fatal("late1m must still be inside the window")
	}
}

// TestMemoryBound fills the whole window with distinct addresses and
// verifies the live heap stays below 192 MiB.
func TestMemoryBound(t *testing.T) {
	tr := NewTracker()
	const m0 = int64(2_000_000)
	var c uint32
	for m := m0; m < m0+1440; m++ {
		base := m * 60
		for j := 0; j < 1100; j++ {
			c++
			tr.Record(noiseIP(uint16(m-m0), c), base+int64(j%60))
		}
	}
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	const limit = 192 << 20
	t.Logf("HeapAlloc after GC with full window: %.1f MiB (limit 192 MiB)",
		float64(ms.HeapAlloc)/(1<<20))
	if ms.HeapAlloc > limit {
		t.Fatalf("HeapAlloc %d exceeds 192 MiB", ms.HeapAlloc)
	}
	runtime.KeepAlive(tr)
}
