package topk

import (
	"net/netip"
	"sync"
	"testing"
)

func mustIP(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func findEntry(top []TopEntry, ip netip.Addr) (TopEntry, bool) {
	for _, e := range top {
		if e.IP == ip {
			return e, true
		}
	}
	return TopEntry{}, false
}

// TestWindowBoundary: attacker A is active only in the earliest minute of
// the window, attacker B only in the minute just before it. Both are the
// strongest in the field. A must appear (within the error bound), B must
// not; after the window slides one more minute, A must disappear too.
func TestWindowBoundary(t *testing.T) {
	tr := New()
	A := mustIP("10.0.0.1")
	B := mustIP("10.0.0.2")
	M0 := int64(2_000_000)

	for i := 0; i < 10000; i++ {
		tr.Record(B, (M0-1)*60+int64(i%60))
	}
	for i := 0; i < 10000; i++ {
		tr.Record(A, M0*60+int64(i%60))
	}
	const N = 20000

	// Window = [M0, M0+1439]: A inside, B outside.
	top := tr.Top((M0+1439)*60 + 59)
	e, ok := findEntry(top, A)
	if !ok {
		t.Fatal("A (earliest in-window minute) missing from Top")
	}
	if d := int64(e.Count) - 10000; d < -N/1000 || d > N/1000 {
		t.Fatalf("A count %d violates error bound N/1000=%d", e.Count, N/1000)
	}
	if _, ok := findEntry(top, B); ok {
		t.Fatal("B (one minute before window) must not appear")
	}

	// One minute later the window is [M0+1, M0+1440]: A expires too.
	top = tr.Top((M0 + 1440) * 60)
	if _, ok := findEntry(top, A); ok {
		t.Fatal("A must expire with its minute")
	}
	if len(top) != 0 {
		t.Fatalf("window should be empty, got %d entries", len(top))
	}
	if tr.table.total != 0 {
		t.Fatalf("total = %d after full expiry, want 0", tr.table.total)
	}
}

// TestLateRecords: records arriving 1-2 minutes late must be counted into
// their own minute and expire together with it; records later than the
// grace period may be dropped.
func TestLateRecords(t *testing.T) {
	tr := New()
	H := int64(3_000_000)
	maxTs := H*60 + 45
	marker := mustIP("10.0.0.9")
	L := mustIP("10.0.1.1")
	E := mustIP("10.0.1.2")
	D := mustIP("10.0.1.3")

	tr.Record(marker, maxTs) // establishes maxTs
	// 1-2 minutes late: must count.
	for i := 0; i < 3000; i++ {
		tr.Record(L, (H-1)*60+30) // 75 s late
	}
	for i := 0; i < 2000; i++ {
		tr.Record(L, (H-2)*60+50) // 115 s late
	}
	// Exactly 120 s late: must count.
	for i := 0; i < 100; i++ {
		tr.Record(E, (H-2)*60+45)
	}
	// 165 s late and 3 minutes back: may be dropped.
	for i := 0; i < 5000; i++ {
		tr.Record(D, (H-3)*60+10)
	}

	if got, want := tr.table.total, uint64(5101); got != want {
		t.Fatalf("total = %d, want %d (late records miscounted)", got, want)
	}

	top := tr.Top(maxTs)
	if e, ok := findEntry(top, L); !ok || e.Count != 5000 {
		t.Fatalf("L = %+v ok=%v, want count 5000", e, ok)
	}
	if e, ok := findEntry(top, E); !ok || e.Count != 100 {
		t.Fatalf("E = %+v ok=%v, want count 100", e, ok)
	}
	if _, ok := findEntry(top, D); ok {
		t.Fatal("D arrived past the grace period and must not be counted")
	}

	// Window [H-2, H+1437]: L's minutes H-2 and H-1 both inside.
	top = tr.Top((H+1437)*60 + 59)
	if e, ok := findEntry(top, L); !ok || e.Count != 5000 {
		t.Fatalf("L before expiry = %+v ok=%v, want 5000", e, ok)
	}
	if e, ok := findEntry(top, E); !ok || e.Count != 100 {
		t.Fatalf("E before expiry = %+v ok=%v, want 100", e, ok)
	}
	// Window [H-1, H+1438]: minute H-2 expired, L keeps only 3000.
	top = tr.Top((H + 1438) * 60)
	if e, ok := findEntry(top, L); !ok || e.Count != 3000 {
		t.Fatalf("L after H-2 expiry = %+v ok=%v, want 3000", e, ok)
	}
	if _, ok := findEntry(top, E); ok {
		t.Fatal("E must expire together with minute H-2")
	}
	// Window [H, H+1439]: L's minutes expired, L must be gone.
	top = tr.Top((H + 1439) * 60)
	if _, ok := findEntry(top, L); ok {
		t.Fatal("L must expire together with its minutes")
	}
	if _, ok := findEntry(top, E); ok {
		t.Fatal("E must expire together with its minute")
	}
	if got, want := tr.table.total, uint64(1); got != want {
		t.Fatalf("total = %d, want 1 (only the marker remains)", got)
	}
}

// TestConcurrentSmoke hammers Record from several goroutines while Top runs
// concurrently, then checks the total. Run with -race for full effect.
func TestConcurrentSmoke(t *testing.T) {
	tr := New()
	base := int64(4_000_000) * 60
	const workers = 8
	const perWorker = 20000
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				var b [16]byte
				n := w*perWorker + i
				b[0] = byte(n)
				b[1] = byte(n >> 8)
				b[2] = byte(n >> 16)
				tr.Record(netip.AddrFrom16(b), base+int64(i%120))
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	now := base
loop:
	for {
		select {
		case <-done:
			break loop
		default:
			tr.Top(now)
			now++
		}
	}
	if got, want := tr.table.total, uint64(workers*perWorker); got != want {
		t.Fatalf("total = %d, want %d", got, want)
	}
	top := tr.Top(base + 180)
	if len(top) == 0 || len(top) > topK {
		t.Fatalf("Top returned %d entries", len(top))
	}
	for i := 1; i < len(top); i++ {
		if top[i-1].Count < top[i].Count {
			t.Fatal("Top not sorted by count descending")
		}
	}
}
