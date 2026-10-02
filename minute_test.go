package topk

import (
	"math/rand"
	"testing"
)

// TestMinuteSpaceSaving runs a random stream through one minute summary and
// checks the classic Space-Saving guarantee against exact counts: every
// estimate is within N/minuteCap of the true count, in both directions.
func TestMinuteSpaceSaving(t *testing.T) {
	var b minuteBuf
	b.activate(7)
	rng := rand.New(rand.NewSource(1))
	exact := make(map[[16]byte]uint64)
	var total uint64

	for i := 0; i < 300000; i++ {
		var ip [16]byte
		// Skewed stream: 1000 hot IPs plus random cold ones.
		if rng.Intn(2) == 0 {
			n := rng.Intn(1000)
			ip[0] = byte(n)
			ip[1] = byte(n >> 8)
		} else {
			rng.Read(ip[:])
		}
		ev := b.add(ip)
		exact[ip]++
		total++
		if ev != nil {
			// Evicted counter must equal the minimum counter value.
			var minCnt uint32 = ^uint32(0)
			for j := int32(0); j < b.n; j++ {
				if j == b.heap[0] {
					continue
				}
				if b.entries[j].cnt < minCnt {
					minCnt = b.entries[j].cnt
				}
			}
			if b.n == minuteCap && ev.cnt > minCnt {
				t.Fatalf("evicted cnt %d > min %d", ev.cnt, minCnt)
			}
		}
	}

	bound := total / minuteCap
	// Tracked entries: 0 <= est - true <= bound.
	var sum uint64
	for j := int32(0); j < b.n; j++ {
		e := b.entries[j]
		sum += uint64(e.cnt)
		tru := exact[e.ip]
		est := uint64(e.cnt)
		if est < tru || est-tru > bound {
			t.Fatalf("tracked ip est=%d true=%d bound=%d", est, tru, bound)
		}
	}
	if sum != total {
		t.Fatalf("counter sum = %d, want %d", sum, total)
	}
	// Untracked entries: true <= bound.
	tracked := make(map[[16]byte]bool, b.n)
	for j := int32(0); j < b.n; j++ {
		tracked[b.entries[j].ip] = true
	}
	for ip, tru := range exact {
		if !tracked[ip] && tru > bound {
			t.Fatalf("untracked ip true=%d > bound=%d", tru, bound)
		}
	}
}

func TestMinuteSealAndReset(t *testing.T) {
	var b minuteBuf
	b.activate(3)
	var ip [16]byte
	ip[0] = 1
	b.add(ip)
	b.seal()
	if b.idx != nil || b.heap != nil || b.pos != nil {
		t.Fatal("seal did not release mutable structures")
	}
	if b.n != 1 || b.entries[0].cnt != 1 {
		t.Fatal("seal lost entries")
	}
	b.activate(4)
	if b.n != 0 || b.min != 4 || b.idx == nil {
		t.Fatal("activate did not reset properly")
	}
}
