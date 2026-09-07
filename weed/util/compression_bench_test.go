package util

import (
	"math/rand"
	"testing"
)

// benchFixture builds deterministic synthetic payloads that mimic the content
// shapes SeaweedFS stores: line-delimited JSON records, prose-like text, and
// incompressible-ish binary. The random fixture uses a fixed seed so runs are
// comparable over time.
func benchFixture(kind string, size int) []byte {
	var base []byte
	switch kind {
	case "json":
		base = []byte(`{"user_id":"u-123456","event":"page_view","url":"https://example.com/some/long/path?q=hello","ts":"2026-09-07T10:00:00Z","props":{"ref":"google","session":"abc123"},"metrics":{"load_ms":321,"ttfb_ms":87}}` + "\n")
	case "text":
		base = []byte("The quick brown fox jumps over the lazy dog. SeaweedFS stores billions of small files efficiently using zstd compression by default now. ")
	case "random":
		rnd := rand.New(rand.NewSource(42))
		base = make([]byte, 4096)
		rnd.Read(base)
	}
	out := make([]byte, 0, size)
	for len(out) < size {
		out = append(out, base...)
	}
	return out[:size]
}

func benchmarkCompressData(b *testing.B, kind string, size int) {
	data := benchFixture(kind, size)
	b.Run("gzip", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			if _, err := GzipData(data); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("zstd", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			if _, err := ZstdData(data); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCompressData compares the two auto-compression algorithms the
// upload path picks between. gzip runs at BestSpeed (GzipStream's writer
// pool), zstd at the klauspost default level.
func BenchmarkCompressData(b *testing.B) {
	for _, kind := range []string{"json", "text", "random"} {
		for _, size := range []int{64 << 10, 1 << 20} {
			name := kind + "-" + byteCount(size)
			b.Run(name, func(b *testing.B) { benchmarkCompressData(b, kind, size) })
		}
	}
}

// BenchmarkDecompressData compares read-path decompression of 1 MiB JSON
// stored with either algorithm. DecompressData sniffs the magic bytes, so
// both benchmarks exercise the exact call the volume read handler makes.
func BenchmarkDecompressData(b *testing.B) {
	data := benchFixture("json", 1<<20)
	gz, _ := GzipData(data)
	zs, _ := ZstdData(data)
	b.Run("gzip", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(data)))
		for i := 0; i < b.N; i++ {
			if _, err := DecompressData(gz); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("zstd", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(data)))
		for i := 0; i < b.N; i++ {
			if _, err := DecompressData(zs); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func byteCount(n int) string {
	if n >= 1<<20 {
		return "1MB"
	}
	return "64KB"
}
