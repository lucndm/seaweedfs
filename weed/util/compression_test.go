package util

import (
	"bytes"
	"testing"
)

func TestContentEncodingOf(t *testing.T) {
	gzipData, err := GzipData([]byte("hello world, hello world, hello world"))
	if err != nil {
		t.Fatalf("GzipData: %v", err)
	}
	zstdData, err := ZstdData([]byte("hello world, hello world, hello world"))
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}

	cases := []struct {
		name string
		data []byte
		want string
	}{
		{name: "gzip magic", data: gzipData, want: "gzip"},
		{name: "zstd magic", data: zstdData, want: "zstd"},
		{name: "plain text", data: []byte("plain text payload"), want: ""},
		{name: "empty", data: nil, want: ""},
		{name: "gzip magic prefix only", data: []byte{0x1f, 0x8b}, want: "gzip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ContentEncodingOf(c.data); got != c.want {
				t.Fatalf("ContentEncodingOf(%q) = %q, want %q", c.name, got, c.want)
			}
		})
	}

	// round trip: the sniffed encoding must decompress via DecompressData
	for name, data := range map[string][]byte{"gzip": gzipData, "zstd": zstdData} {
		decoded, err := DecompressData(data)
		if err != nil {
			t.Fatalf("%s: DecompressData: %v", name, err)
		}
		if !bytes.Equal(decoded, []byte("hello world, hello world, hello world")) {
			t.Fatalf("%s: round trip mismatch", name)
		}
	}
}

// TestZstdDefaultCompressesAtLeastAsWellAsGzip pins the reason zstd is the
// default upload compression: on compressable content it must not produce
// bigger frames than the gzip BestSpeed writer it replaced. The fixtures are
// deterministic and the compress library is pinned in go.mod, so the
// comparison is stable.
func TestZstdDefaultCompressesAtLeastAsWellAsGzip(t *testing.T) {
	fixtures := map[string][]byte{
		"json": bytes.Repeat([]byte(`{"event":"page_view","url":"https://example.com/path","ts":"2026-09-07T10:00:00Z"}`+"\n"), 512),
		"text": bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 512),
	}
	for name, data := range fixtures {
		gz, err := GzipData(data)
		if err != nil {
			t.Fatalf("%s: GzipData: %v", name, err)
		}
		zs, err := ZstdData(data)
		if err != nil {
			t.Fatalf("%s: ZstdData: %v", name, err)
		}
		if len(zs) > len(gz) {
			t.Fatalf("%s: zstd frame %d bytes is bigger than gzip %d bytes on compressable data", name, len(zs), len(gz))
		}
	}
}
