package topk

import "encoding/binary"

// tableBits gives 2^21 slots, enough for the hard upper bound of live
// distinct IPs (1443 live minutes * minuteCap) at load factor <= 0.69.
// The size is fixed so no rehash ever happens on the hot path.
const tableBits = 21

// ipTable is an open-addressing hash table (linear probing, backward-shift
// deletion) mapping a 16-byte IP to its merged count across all live
// minute summaries. A zero value in vals marks an empty slot; counts are
// always >= 1, and entries are deleted as soon as they reach zero.
type ipTable struct {
	keys  [][16]byte
	vals  []uint64
	count int    // number of occupied slots
	total uint64 // sum of all vals: exact number of records in the window
}

// init allocates the fixed-size table.
func (t *ipTable) init() {
	n := 1 << tableBits
	t.keys = make([][16]byte, n)
	t.vals = make([]uint64, n)
}

func hashIP(ip [16]byte) uint64 {
	lo := binary.LittleEndian.Uint64(ip[:8])
	hi := binary.LittleEndian.Uint64(ip[8:])
	h := lo*0x9E3779B97F4A7C15 + hi*0xC2B2AE3D27D4EB4F
	h ^= h >> 29
	h *= 0xBF58476D1CE4E5B9
	h ^= h >> 32
	return h
}

// find returns the slot of ip, or the first empty slot on its probe chain
// when ip is absent.
func (t *ipTable) find(ip [16]byte) int {
	mask := uint64(len(t.vals) - 1)
	i := hashIP(ip) & mask
	for t.vals[i] != 0 {
		if t.keys[i] == ip {
			return int(i)
		}
		i = (i + 1) & mask
	}
	return int(i)
}

// get returns the count of ip and whether it is present. Used by tests.
func (t *ipTable) get(ip [16]byte) (uint64, bool) {
	i := t.find(ip)
	if t.vals[i] == 0 {
		return 0, false
	}
	return t.vals[i], true
}

// add increments the count of ip by delta, inserting it if absent.
func (t *ipTable) add(ip [16]byte, delta uint64) {
	i := t.find(ip)
	if t.vals[i] == 0 {
		t.keys[i] = ip
		t.count++
	}
	t.vals[i] += delta
	t.total += delta
}

// sub decrements the count of ip by delta, deleting the entry when it
// reaches zero. ip must be present with count >= delta.
func (t *ipTable) sub(ip [16]byte, delta uint64) {
	i := t.find(ip)
	v := t.vals[i]
	if v == 0 || v < delta {
		panic("topk: ipTable.sub underflow")
	}
	t.total -= delta
	if v == delta {
		t.deleteSlot(i)
		t.count--
		return
	}
	t.vals[i] = v - delta
}

// deleteSlot removes the entry at slot i and repairs the probe chain by
// backward-shift deletion (Knuth TAOCP 6.4, Algorithm R).
func (t *ipTable) deleteSlot(del int) {
	mask := len(t.vals) - 1
	j := del
	i := del
	for {
		t.vals[j] = 0
		for {
			i = (i + 1) & mask
			if t.vals[i] == 0 {
				return
			}
			r := int(hashIP(t.keys[i]) & uint64(mask))
			if !inArc(r, j, i) {
				break
			}
		}
		t.keys[j] = t.keys[i]
		t.vals[j] = t.vals[i]
		j = i
	}
}

// inArc reports whether r lies in the cyclic half-open arc (j, i].
func inArc(r, j, i int) bool {
	if j < i {
		return r > j && r <= i
	}
	return r > j || r <= i
}

// clear removes all entries.
func (t *ipTable) clear() {
	for i := range t.vals {
		t.vals[i] = 0
	}
	t.count = 0
	t.total = 0
}
