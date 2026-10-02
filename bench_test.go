package topk

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// uniqueIP maps a counter to a distinct IPv6 address.
func uniqueIP(c uint64) netip.Addr {
	var b [16]byte
	b[0] = 0x20
	binary.BigEndian.PutUint64(b[8:], c)
	return netip.AddrFrom16(b)
}

// BenchmarkRecordWorstCase measures Record throughput on the worst input:
// a single goroutine where every record carries a brand-new address.
func BenchmarkRecordWorstCase(b *testing.B) {
	tr := New()
	ts := int64(60_000_000) * 60
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Record(uniqueIP(uint64(i)+1), ts+int64(i/200000))
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "rec/s")
}

// BenchmarkFullWindow fills the window completely (1440 minutes, every
// minute's summary full, merged table at its 1.44M-entry maximum) and
// reports the max single-call latency of Record and Top while the window
// slides, plus the post-GC heap size.
func BenchmarkFullWindow(b *testing.B) {
	tr := New()
	base := int64(60_000_000)
	var c uint64
	rec := func(ts int64) {
		c++
		tr.Record(uniqueIP(c), ts)
	}
	// Fill the window: 2000 distinct records per minute (summary cap is
	// 1000, so every minute also exercises eviction).
	for m := 0; m < windowMinutes; m++ {
		for j := 0; j < 2000; j++ {
			rec((base + int64(m)) * 60)
		}
	}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.ReportMetric(float64(ms.HeapAlloc)/(1<<20), "heap-MiB")

	// Slide the window by 60 minutes, one minute at a time, keeping it
	// full; measure the max latency of every single Record and Top call.
	var maxRec, maxTop time.Duration
	for m := int64(0); m < 60; m++ {
		minStart := (base + windowMinutes + m) * 60
		for j := 0; j < 2000; j++ {
			start := time.Now()
			rec(minStart)
			if d := time.Since(start); d > maxRec {
				maxRec = d
			}
		}
		start := time.Now()
		tr.Top(minStart + 59)
		if d := time.Since(start); d > maxTop {
			maxTop = d
		}
	}
	b.ReportMetric(float64(maxRec.Microseconds())/1000, "rec-max-ms")
	b.ReportMetric(float64(maxTop.Microseconds())/1000, "top-max-ms")
}
