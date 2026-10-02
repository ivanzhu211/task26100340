package topip

import "encoding/binary"

// aggBits sizes the aggregate table. The aggregate holds at most
// windowMinutes*slotCap = 1,440,000 distinct keys, so 2^21 slots keep
// the load factor below 0.69 and no growth is ever needed.
const aggBits = 21
const aggSize = 1 << aggBits
const aggMask = aggSize - 1

// The table is divided into blocks of 256 slots; blockMax caches the
// largest count in each block so Top can skip blocks that cannot
// contain a top-50 candidate.
const aggBlockShift = 8
const aggBlockSize = 1 << aggBlockShift
const aggBlocks = aggSize >> aggBlockShift

// aggTable is an open-addressing hash table mapping an IP key to the
// sum of its Space-Saving estimates over all live minute slots.
// A zero count marks an empty slot; keys are deleted as soon as their
// summed estimate returns to zero.
type aggTable struct {
	keys     [][16]byte
	counts   []uint64
	blockMax []uint64
	n        int
}

func (a *aggTable) init() {
	a.keys = make([][16]byte, aggSize)
	a.counts = make([]uint64, aggSize)
	a.blockMax = make([]uint64, aggBlocks)
}

// hash16 mixes a 16-byte IP key into a 64-bit hash.
func hash16(k [16]byte) uint64 {
	x := binary.LittleEndian.Uint64(k[:8])
	y := binary.LittleEndian.Uint64(k[8:])
	h := x*0x9E3779B97F4A7C15 ^ y
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	return h
}

// add increases the aggregate count of key by delta, inserting the
// key if necessary.
func (a *aggTable) add(key [16]byte, delta uint64) {
	i := hash16(key) & aggMask
	for a.counts[i] != 0 {
		if a.keys[i] == key {
			a.counts[i] += delta
			if a.counts[i] > a.blockMax[i>>aggBlockShift] {
				a.blockMax[i>>aggBlockShift] = a.counts[i]
			}
			return
		}
		i = (i + 1) & aggMask
	}
	a.keys[i] = key
	a.counts[i] = delta
	if delta > a.blockMax[i>>aggBlockShift] {
		a.blockMax[i>>aggBlockShift] = delta
	}
	a.n++
}

// sub decreases the aggregate count of key by delta, deleting the key
// when its count reaches zero. key must be present with count >= delta.
func (a *aggTable) sub(key [16]byte, delta uint64) {
	i := hash16(key) & aggMask
	for a.counts[i] != 0 {
		if a.keys[i] == key {
			old := a.counts[i]
			a.counts[i] -= delta
			if a.counts[i] == 0 {
				lo, hi := a.deleteAt(i)
				a.recomputeBlocks(lo, hi)
			} else if old == a.blockMax[i>>aggBlockShift] {
				a.recomputeBlock(i >> aggBlockShift)
			}
			return
		}
		i = (i + 1) & aggMask
	}
}

// deleteAt removes the (empty) slot i using backward-shift deletion,
// keeping the linear-probing invariant intact. It returns the cyclic
// slot range [lo, hi] whose contents were modified.
func (a *aggTable) deleteAt(i uint64) (lo, hi uint64) {
	a.n--
	lo = i
	j := i
	for {
		a.counts[i] = 0
		for {
			j = (j + 1) & aggMask
			if a.counts[j] == 0 {
				return lo, j
			}
			k := hash16(a.keys[j]) & aggMask
			// Slot j can move into i iff its home position k is not in
			// the cyclic interval (i, j].
			if (i <= j && (k <= i || k > j)) || (i > j && k <= i && k > j) {
				a.keys[i] = a.keys[j]
				a.counts[i] = a.counts[j]
				i = j
				break
			}
		}
	}
}

// recomputeBlock recomputes the cached maximum of one block.
func (a *aggTable) recomputeBlock(b uint64) {
	base := b << aggBlockShift
	var m uint64
	for _, c := range a.counts[base : base+aggBlockSize] {
		if c > m {
			m = c
		}
	}
	a.blockMax[b] = m
}

// recomputeBlocks recomputes the cached maxima of all blocks touching
// the cyclic slot range [lo, hi].
func (a *aggTable) recomputeBlocks(lo, hi uint64) {
	for b := lo >> aggBlockShift; ; b = (b + 1) & (aggBlocks - 1) {
		a.recomputeBlock(b)
		if b == hi>>aggBlockShift {
			return
		}
	}
}
