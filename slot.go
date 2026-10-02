package topip

// slotCap is the number of Space-Saving counters kept per minute.
// With slotCap counters, a minute summary overestimates any single
// IP's count by at most (records in that minute)/slotCap, so summing
// over the 1440-minute window bounds the total error by N/slotCap.
const slotCap = 1000

// idxSize is the size of the per-slot open-addressing index. With at
// most slotCap entries the load factor stays below 0.5.
const idxSize = 2048
const idxMask = idxSize - 1

// slotEntry is one Space-Saving counter inside a minute slot.
type slotEntry struct {
	key   [16]byte
	count uint64
}

// minuteSlot is a Space-Saving summary of one minute of records. All
// storage is fixed-size; nothing per-record is ever allocated.
type minuteSlot struct {
	entries [slotCap]slotEntry
	heap    [slotCap]int32
	hpos    [slotCap]int32
	idx     [idxSize]int16 // entry index+1 per hash slot, 0 = empty
	n       int
	minute  int64
}

func newMinuteSlot(minute int64) *minuteSlot {
	return &minuteSlot{minute: minute}
}

// locate returns the hash slot where key is or should be inserted.
func (s *minuteSlot) locate(key [16]byte) int {
	i := hash16(key) & idxMask
	for v := s.idx[i]; v != 0; v = s.idx[i] {
		if s.entries[v-1].key == key {
			break
		}
		i = (i + 1) & idxMask
	}
	return int(i)
}

// idxDelete removes key from the index using backward-shift deletion,
// keeping the linear-probing invariant intact. key must be present.
func (s *minuteSlot) idxDelete(key [16]byte) {
	i := s.locate(key)
	j := i
	for {
		s.idx[i] = 0
		for {
			j = (j + 1) & idxMask
			v := s.idx[j]
			if v == 0 {
				return
			}
			k := int(hash16(s.entries[v-1].key) & idxMask)
			// Entry j can move into i iff its home slot is not in the
			// cyclic interval (i, j].
			if (i <= j && (k <= i || k > j)) || (i > j && k <= i && k > j) {
				s.idx[i] = v
				i = j
				break
			}
		}
	}
}

// add records one occurrence of key in this minute, updating agg.
//
// Space-Saving: a known key just increments its counter; a new key
// takes a free counter while the minute has fewer than slotCap of
// them; otherwise the minimum counter is evicted and reused with
// value min+1. The overestimate of any counter never exceeds the
// current minimum counter, which is at most (records this
// minute)/slotCap.
func (s *minuteSlot) add(key [16]byte, agg *aggTable) {
	i := s.locate(key)
	if v := s.idx[i]; v != 0 {
		p := int(v - 1)
		s.entries[p].count++
		s.siftDown(int(s.hpos[p]))
		agg.add(key, 1)
		return
	}
	if s.n < slotCap {
		p := s.n
		s.n++
		s.entries[p] = slotEntry{key: key, count: 1}
		s.idx[i] = int16(p + 1)
		s.heap[p] = int32(p)
		s.hpos[p] = int32(p)
		s.siftUp(p)
		agg.add(key, 1)
		return
	}
	// Evict the minimum counter and reuse it for the new key.
	p := int(s.heap[0])
	old := s.entries[p]
	agg.sub(old.key, old.count)
	s.idxDelete(old.key)
	// The deletion above may have shifted index entries, so the
	// insert slot for key must be recomputed.
	i = s.locate(key)
	s.entries[p] = slotEntry{key: key, count: old.count + 1}
	s.idx[i] = int16(p + 1)
	agg.add(key, old.count+1)
	s.siftDown(0)
}

// lessHeap reports whether heap position a orders before b
// (min-heap by counter value).
func (s *minuteSlot) lessHeap(a, b int) bool {
	return s.entries[s.heap[a]].count < s.entries[s.heap[b]].count
}

func (s *minuteSlot) swapHeap(a, b int) {
	s.heap[a], s.heap[b] = s.heap[b], s.heap[a]
	s.hpos[s.heap[a]] = int32(a)
	s.hpos[s.heap[b]] = int32(b)
}

func (s *minuteSlot) siftUp(hi int) {
	for hi > 0 {
		parent := (hi - 1) / 2
		if !s.lessHeap(hi, parent) {
			return
		}
		s.swapHeap(hi, parent)
		hi = parent
	}
}

func (s *minuteSlot) siftDown(hi int) {
	for {
		l := 2*hi + 1
		if l >= s.n {
			return
		}
		m := l
		if r := l + 1; r < s.n && s.lessHeap(r, l) {
			m = r
		}
		if !s.lessHeap(m, hi) {
			return
		}
		s.swapHeap(m, hi)
		hi = m
	}
}
