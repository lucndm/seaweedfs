package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/util"
)

// startNegotiatingVolumeStandIn mimics the volume server read handler's
// Accept-Encoding negotiation for a compressed needle (volume_server_handlers_
// read.go): pass frames through with a matching Content-Encoding when the
// client advertises the algorithm, otherwise decompress and serve clear data.
func startNegotiatingVolumeStandIn(t *testing.T, stored []byte) (url string, sawHeader func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var reqHeader http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqHeader = r.Header.Clone()
		mu.Unlock()
		ae := r.Header.Get("Accept-Encoding")
		if strings.Contains(ae, "zstd") && util.IsZstdContent(stored) {
			w.Header().Set("Content-Encoding", "zstd")
			_, _ = w.Write(stored)
			return
		}
		if strings.Contains(ae, "gzip") && util.IsGzippedContent(stored) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(stored)
			return
		}
		clear, err := util.DecompressData(stored)
		if err != nil {
			clear = stored
		}
		_, _ = w.Write(clear)
	}))
	t.Cleanup(server.Close)
	return server.URL, func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return reqHeader
	}
}

func readAllViaStream(t *testing.T, url string, isFullChunk bool) []byte {
	t.Helper()
	var got bytes.Buffer
	retryable, err := ReadUrlAsStream(context.Background(), url, "", nil, true, isFullChunk, 0, 0, func(data []byte) {
		got.Write(data)
	})
	if err != nil {
		t.Fatalf("ReadUrlAsStream: %v (retryable=%v)", err, retryable)
	}
	return got.Bytes()
}

// TestReadUrlAsStreamNegotiatesZstdPassThrough pins the chunk-fetch
// negotiation: a full-chunk fetch advertises zstd, and a zstd response body is
// decoded before the callback sees it, so callers always receive clear data.
func TestReadUrlAsStreamNegotiatesZstdPassThrough(t *testing.T) {
	clear := bytes.Repeat([]byte("zstd negotiated chunk fetch! "), 1024)

	stored, err := util.ZstdData(clear)
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}
	url, sawHeader := startNegotiatingVolumeStandIn(t, stored)

	got := readAllViaStream(t, url, true)

	if !strings.Contains(sawHeader().Get("Accept-Encoding"), "zstd") {
		t.Fatalf("full-chunk fetch must advertise zstd, got Accept-Encoding %q", sawHeader().Get("Accept-Encoding"))
	}
	if !bytes.Equal(got, clear) {
		t.Fatalf("callback data mismatch: got %d bytes, want %d clear bytes", len(got), len(clear))
	}
}

func TestReadUrlAsStreamGzipPassThroughStillWorks(t *testing.T) {
	clear := bytes.Repeat([]byte("legacy gzip chunk fetch! "), 1024)

	stored, err := util.GzipData(clear)
	if err != nil {
		t.Fatalf("GzipData: %v", err)
	}
	url, _ := startNegotiatingVolumeStandIn(t, stored)

	got := readAllViaStream(t, url, true)
	if !bytes.Equal(got, clear) {
		t.Fatalf("callback data mismatch: got %d bytes, want %d clear bytes", len(got), len(clear))
	}
}

func TestReadUrlAsStreamUncompressedBodyUnchanged(t *testing.T) {
	clear := []byte("plain stored chunk, no compression flag")
	url, _ := startNegotiatingVolumeStandIn(t, clear)

	got := readAllViaStream(t, url, true)
	if !bytes.Equal(got, clear) {
		t.Fatalf("callback data mismatch for uncompressed body")
	}
}

// TestReadUrlAsStreamPartialFetchHasNoAcceptEncoding pins that ranged chunk
// fetches keep negotiating nothing: the volume server has no way to slice
// compressed frames, so a Range request must be served as clear bytes.
func TestReadUrlAsStreamPartialFetchHasNoAcceptEncoding(t *testing.T) {
	clear := bytes.Repeat([]byte("ranged chunk fetch! "), 1024)
	stored, err := util.ZstdData(clear)
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}
	url, sawHeader := startNegotiatingVolumeStandIn(t, stored)

	got := readAllViaStream(t, url, false)

	if ae := sawHeader().Get("Accept-Encoding"); ae != "" {
		t.Fatalf("partial fetch must not send Accept-Encoding, got %q", ae)
	}
	if rg := sawHeader().Get("Range"); rg == "" {
		t.Fatalf("partial fetch must send a Range header")
	}
	// the stand-in decompresses for non-advertising clients, like the volume
	if !bytes.Equal(got, clear) {
		t.Fatalf("callback data mismatch: got %d bytes, want %d clear bytes", len(got), len(clear))
	}
}

// TestPooledZstdDecoderReuse exercises the pool checkout/return path used by
// the zstd response decoding above.
func TestPooledZstdDecoderReuse(t *testing.T) {
	clear := []byte("pool me once, pool me twice")
	for i := 0; i < 3; i++ {
		stored, err := util.ZstdData(clear)
		if err != nil {
			t.Fatalf("ZstdData: %v", err)
		}
		zr, err := util.GetPooledZstdDecoder(bytes.NewReader(stored))
		if err != nil {
			t.Fatalf("GetPooledZstdDecoder: %v", err)
		}
		got, err := io.ReadAll(zr)
		util.PutPooledZstdDecoder(zr)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(got, clear) {
			t.Fatalf("round %d: decoded mismatch", i)
		}
	}
}

// benchmarkJsonChunk builds a pseudo-random JSON-lines chunk so the zstd
// ratio is moderate (like real logs), not the extreme of repeated text.
func benchmarkJsonChunk(size int) []byte {
	rnd := rand.New(rand.NewSource(7))
	var b bytes.Buffer
	for b.Len() < size {
		fmt.Fprintf(&b, `{"ts":"2026-09-07T10:%02d:%02d.%03dZ","level":"info","user":%d,"req_id":"%08x%08x","path":"/api/v1/items/%d","latency_ms":%d.%d,"bytes_out":%d}`+"\n",
			rnd.Intn(60), rnd.Intn(60), rnd.Intn(1000), rnd.Intn(1000000),
			rnd.Uint32(), rnd.Uint32(), rnd.Intn(100000), rnd.Intn(900), rnd.Intn(10), rnd.Intn(1<<20))
	}
	return b.Bytes()[:size]
}

// benchmarkFetchServer stands in for the volume server and counts wire bytes.
// passthrough=true mimics the negotiated behavior (compressed frames on the
// wire for zstd needles); false mimics the pre-negotiation behavior (the
// volume decompressed every zstd needle before answering).
func benchmarkFetchServer(b *testing.B, stored, clear []byte, passthrough bool) (url string, wireBytes *uint64) {
	wireBytes = new(uint64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if passthrough && strings.Contains(r.Header.Get("Accept-Encoding"), "zstd") && util.IsZstdContent(stored) {
			w.Header().Set("Content-Encoding", "zstd")
			atomic.AddUint64(wireBytes, uint64(len(stored)))
			_, _ = w.Write(stored)
			return
		}
		atomic.AddUint64(wireBytes, uint64(len(clear)))
		_, _ = w.Write(clear)
	}))
	b.Cleanup(server.Close)
	return server.URL, wireBytes
}

// BenchmarkChunkFetchZstdNeedle compares fetching a full zstd needle with the
// frames passed through compressed (current behavior, "compressed-wire")
// against the volume decompressing each fetch ("clear-wire", the behavior
// before Accept-Encoding negotiation). Throughput is clear bytes delivered;
// wire-B/op shows what actually crossed the connection.
func BenchmarkChunkFetchZstdNeedle(b *testing.B) {
	clear := benchmarkJsonChunk(1 << 20)
	stored, err := util.ZstdData(clear)
	if err != nil {
		b.Fatalf("ZstdData: %v", err)
	}

	for _, mode := range []struct {
		name        string
		passthrough bool
	}{
		{name: "compressed-wire", passthrough: true},
		{name: "clear-wire", passthrough: false},
	} {
		b.Run(mode.name, func(b *testing.B) {
			url, wireBytes := benchmarkFetchServer(b, stored, clear, mode.passthrough)
			b.ReportAllocs()
			b.SetBytes(int64(len(clear)))
			var got bytes.Buffer
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got.Reset()
				if _, err := ReadUrlAsStream(context.Background(), url, "", nil, true, true, 0, 0, func(data []byte) {
					got.Write(data)
				}); err != nil {
					b.Fatalf("ReadUrlAsStream: %v", err)
				}
				if !bytes.Equal(got.Bytes(), clear) {
					b.Fatalf("data mismatch")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(*wireBytes)/float64(b.N), "wire-B/op")
			b.ReportMetric(100*float64(*wireBytes)/float64(b.N)/float64(len(clear)), "wire-%")
		})
	}
}
