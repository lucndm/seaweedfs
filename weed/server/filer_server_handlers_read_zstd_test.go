package weed_server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/filer"
	"github.com/seaweedfs/seaweedfs/weed/util"
)

func zstdTestRequest(t *testing.T, method, path, acceptEncoding, rangeHeader string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	if acceptEncoding != "" {
		r.Header.Set("Accept-Encoding", acceptEncoding)
	}
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	return r
}

func runProcessRangeRequest(t *testing.T, r *http.Request, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	zw := newZstdAwareWriter(rec, r)
	err := ProcessRangeRequest(r, zw, int64(len(body)), "application/octet-stream", func(offset int64, size int64) (filer.DoStreamContent, error) {
		return func(writer io.Writer) error {
			_, err := writer.Write(body[offset : offset+size])
			return err
		}, nil
	})
	if err != nil {
		t.Fatalf("ProcessRangeRequest: %v", err)
	}
	zw.Finalize()
	return rec
}

// TestZstdAwareWriterPassthroughWithAcceptEncoding mirrors the volume read
// handler: advertising clients get the stored frames plus the header.
func TestZstdAwareWriterPassthroughWithAcceptEncoding(t *testing.T) {
	plain := bytes.Repeat([]byte("zstd-roundtrip-test-line-"), 800)
	stored, err := util.ZstdData(plain)
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}

	r := zstdTestRequest(t, http.MethodGet, "/buckets/plane/.zstd-test/payload.bin", "zstd", "")
	rec := runProcessRangeRequest(t, r, stored)

	if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), stored) {
		t.Fatalf("body must be the raw zstd frames (got %d bytes, want %d)", rec.Body.Len(), len(stored))
	}
}

// TestZstdAwareWriterTransparentDecode covers the gap this fork fixes: plain
// clients must receive the decompressed bytes, not the stored frames.
func TestZstdAwareWriterTransparentDecode(t *testing.T) {
	plain := bytes.Repeat([]byte("zstd-roundtrip-test-line-"), 800)
	stored, err := util.ZstdData(plain)
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}

	r := zstdTestRequest(t, http.MethodGet, "/buckets/plane/.zstd-test/payload.bin", "identity", "")
	rec := runProcessRangeRequest(t, r, stored)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want empty (decoded size is unknown)", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), plain) {
		t.Fatalf("body must be decoded plain data (got %d bytes, want %d)", rec.Body.Len(), len(plain))
	}
}

// TestZstdAwareWriterPlainPassthrough: non-zstd content must flow through
// untouched, no Vary noise, no header.
func TestZstdAwareWriterPlainPassthrough(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 4096)

	r := zstdTestRequest(t, http.MethodGet, "/buckets/plane/plain.bin", "", "")
	rec := runProcessRangeRequest(t, r, body)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := rec.Header().Get("Vary"); strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, must not mention Accept-Encoding for plain content", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatalf("body must be untouched")
	}
}

// TestZstdAwareWriterRangeAdvertised: ranges index the stored bytes, so an
// advertising client gets raw frames with the header. The header must be set
// via PreDecide (the head probe), because WriteHeader(206) runs before the
// body streams.
func TestZstdAwareWriterRangeAdvertised(t *testing.T) {
	plain := bytes.Repeat([]byte("zstd-roundtrip-test-line-"), 800)
	stored, err := util.ZstdData(plain)
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}

	r := zstdTestRequest(t, http.MethodGet, "/buckets/plane/.zstd-test/payload.bin", "zstd", "bytes=0-9")
	rec := httptest.NewRecorder()
	zw := newZstdAwareWriter(rec, r)
	zw.PreDecide(util.IsZstdContent(stored[:4]))
	err = ProcessRangeRequest(r, zw, int64(len(stored)), "application/octet-stream", func(offset int64, size int64) (filer.DoStreamContent, error) {
		return func(writer io.Writer) error {
			_, err := writer.Write(stored[offset : offset+size])
			return err
		}, nil
	})
	if err != nil {
		t.Fatalf("ProcessRangeRequest: %v", err)
	}
	zw.Finalize()

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), stored[:10]) {
		t.Fatalf("body must be the first 10 stored bytes")
	}
}
