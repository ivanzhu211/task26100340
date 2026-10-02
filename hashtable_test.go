package topk

import (
	"math/rand"
	"testing"
)

func TestTableAddSubDelete(t *testing.T) {
	var tab ipTable
	tab.init()
	ref := make(map[[16]byte]uint64)
	rng := rand.New(rand.NewSource(42))

	var keys [][16]byte
	for iter := 0; iter < 200000; iter++ {
		var ip [16]byte
		if len(keys) > 0 && rng.Intn(3) > 0 {
			ip = keys[rng.Intn(len(keys))]
		} else {
			rng.Read(ip[:])
			keys = append(keys, ip)
		}
		delta := uint64(rng.Intn(10) + 1)
		if rng.Intn(2) == 0 {
			tab.add(ip, delta)
			ref[ip] += delta
		} else if cur := ref[ip]; cur > 0 {
			d := delta
			if d > cur {
				d = cur
			}
			tab.sub(ip, d)
			if cur == d {
				delete(ref, ip)
			} else {
				ref[ip] = cur - d
			}
		}
	}

	if tab.count != len(ref) {
		t.Fatalf("count = %d, want %d", tab.count, len(ref))
	}
	var wantTotal uint64
	for ip, want := range ref {
		wantTotal += want
		got, ok := tab.get(ip)
		if !ok || got != want {
			t.Fatalf("get(%x) = %d,%v want %d", ip, got, ok, want)
		}
	}
	if tab.total != wantTotal {
		t.Fatalf("total = %d, want %d", tab.total, wantTotal)
	}
	// No stale entries: every occupied slot must be in ref.
	for i, v := range tab.vals {
		if v != 0 {
			if want, ok := ref[tab.keys[i]]; !ok || want != v {
				t.Fatalf("stale slot %d: ip=%x v=%d", i, tab.keys[i], v)
			}
		}
	}
}

func TestTableClear(t *testing.T) {
	var tab ipTable
	tab.init()
	var ip [16]byte
	for i := 0; i < 1000; i++ {
		ip[0] = byte(i)
		ip[1] = byte(i >> 8)
		tab.add(ip, 3)
	}
	tab.clear()
	if tab.count != 0 || tab.total != 0 {
		t.Fatalf("after clear: count=%d total=%d", tab.count, tab.total)
	}
	tab.add(ip, 1)
	if got, ok := tab.get(ip); !ok || got != 1 {
		t.Fatalf("after clear+add: got %d,%v", got, ok)
	}
}
