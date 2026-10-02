package topk

// minuteCap is the number of Space-Saving counters kept per minute. The
// per-minute estimate error is bounded by N_minute/minuteCap, so summing
// over the window bounds the total error by N/minuteCap = N/1000.
const minuteCap = 1000

// ringSize is the number of minute buffers. It must exceed the maximum
// number of simultaneously live minutes (1440 window + 2 late-arrival
// grace + current) and is a power of two for cheap indexing.
const ringSize = 2048

// minuteEntry is one Space-Saving counter inside a minute summary.
type minuteEntry struct {
	ip  [16]byte
	cnt uint32
}

// minuteBuf is one minute's Space-Saving summary: a fixed-size array of
// counters plus, while the minute is still mutable (current minute and the
// two previous ones, to accept late records), a lookup map and a min-heap
// for O(log n) eviction. Map and heap are released once the minute seals.
type minuteBuf struct {
	entries [minuteCap]minuteEntry
	n       int32 // number of used slots in entries
	min     int64 // which minute this buffer currently holds; -1 when empty

	idx  map[[16]byte]int32 // ip -> slot, mutable phase only
	heap []int32            // slot indices as a min-heap ordered by cnt
	pos  []int32            // slot -> position in heap
}

// reset clears the buffer for reuse by a new minute, dropping any
// mutable-phase structures.
func (b *minuteBuf) reset(min int64) {
	b.n = 0
	b.min = min
	b.idx = nil
	b.heap = nil
	b.pos = nil
}

// activate turns the buffer into a mutable summary for minute min.
func (b *minuteBuf) activate(min int64) {
	b.reset(min)
	b.idx = make(map[[16]byte]int32, minuteCap)
	b.heap = make([]int32, 0, minuteCap)
	b.pos = make([]int32, minuteCap)
}

// seal drops the mutable-phase structures; the entries array is kept for
// window expiry and merging.
func (b *minuteBuf) seal() {
	b.idx = nil
	b.heap = nil
	b.pos = nil
}

// add records one hit for ip. If the summary is full and ip is new, the
// minimum counter is evicted and returned in evicted so the caller can
// mirror the change into the global merged table.
func (b *minuteBuf) add(ip [16]byte) (evicted *minuteEntry) {
	if slot, ok := b.idx[ip]; ok {
		b.entries[slot].cnt++
		b.siftDown(b.pos[slot])
		return nil
	}
	if b.n < minuteCap {
		slot := b.n
		b.n++
		b.entries[slot] = minuteEntry{ip: ip, cnt: 1}
		b.idx[ip] = slot
		b.heapPush(slot)
		return nil
	}
	// Full: evict the minimum counter (heap root) and reassign its slot.
	slot := b.heap[0]
	old := b.entries[slot]
	delete(b.idx, old.ip)
	b.entries[slot] = minuteEntry{ip: ip, cnt: old.cnt + 1}
	b.idx[ip] = slot
	b.siftDown(b.pos[slot])
	return &old
}

func (b *minuteBuf) less(i, j int) bool {
	return b.entries[b.heap[i]].cnt < b.entries[b.heap[j]].cnt
}

func (b *minuteBuf) swap(i, j int) {
	b.heap[i], b.heap[j] = b.heap[j], b.heap[i]
	b.pos[b.heap[i]] = int32(i)
	b.pos[b.heap[j]] = int32(j)
}

func (b *minuteBuf) heapPush(slot int32) {
	b.heap = append(b.heap, slot)
	i := len(b.heap) - 1
	b.pos[slot] = int32(i)
	for i > 0 {
		parent := (i - 1) / 2
		if !b.less(i, parent) {
			break
		}
		b.swap(i, parent)
		i = parent
	}
}

func (b *minuteBuf) siftDown(i int32) {
	n := int32(len(b.heap))
	for {
		smallest := i
		l := 2*i + 1
		r := 2*i + 2
		if l < n && b.less(int(l), int(smallest)) {
			smallest = l
		}
		if r < n && b.less(int(r), int(smallest)) {
			smallest = r
		}
		if smallest == i {
			return
		}
		b.swap(int(i), int(smallest))
		i = smallest
	}
}
