package topip

import (
	"runtime"
	"testing"
	"time"
)

const benchM0 = int64(5_000_000)

// fillWindow feeds perMin distinct addresses into each of the 1440
// window minutes, so every minute slot is at its 1000-counter cap and
// the aggregate holds ~1.44M distinct IPs.
func fillWindow(tr *Tracker, perMin int) {
	var c uint32
	for m := int64(0); m < windowMinutes; m++ {
		base := (benchM0 + m) * 60
		for j := 0; j < perMin; j++ {
			c++
			tr.Record(noiseIP(uint16(m), c), base+int64(j%60))
		}
	}
}

// BenchmarkRecordWorstCase measures Record throughput on the worst
// input: every record carries a brand-new address, so every call
// evicts a counter in a full minute slot.
func BenchmarkRecordWorstCase(b *testing.B) {
	tr := NewTracker()
	fillWindow(tr, 1100)
	ts := (benchM0 + windowMinutes - 1) * 60
	c := uint32(10_000_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c++
		tr.Record(noiseIP(1439, c), ts)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "rec/s")
}

// BenchmarkRecordRollover measures the worst single-call Record
// latency while the window slides across minute boundaries (each
// boundary expires a full 1000-counter minute).
func BenchmarkRecordRollover(b *testing.B) {
	tr := NewTracker()
	fillWindow(tr, 1100)
	ts := (benchM0 + windowMinutes) * 60
	c := uint32(20_000_000)
	var maxD time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c++
		if i%1100 == 0 {
			ts += 60 // cross a minute boundary, expiring the oldest minute
		}
		start := time.Now()
		tr.Record(noiseIP(uint16(windowMinutes+(int64(i)/1100)), c), ts)
		if d := time.Since(start); d > maxD {
			maxD = d
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(maxD)/float64(time.Microsecond), "max_us")
}

// BenchmarkTopFullWindow measures the worst single-call Top latency
// on a full window, and reports the live heap after GC.
func BenchmarkTopFullWindow(b *testing.B) {
	tr := NewTracker()
	fillWindow(tr, 1100)
	now := (benchM0+windowMinutes-1)*60 + 30
	var maxD time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		items := tr.Top(now)
		if d := time.Since(start); d > maxD {
			maxD = d
		}
		if len(items) != topK {
			b.Fatalf("want %d items, got %d", topK, len(items))
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(maxD)/float64(time.Microsecond), "max_us")
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.ReportMetric(float64(ms.HeapAlloc)/float64(1<<20), "heap_mib")
	runtime.KeepAlive(tr)
}
