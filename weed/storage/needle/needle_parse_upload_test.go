package needle

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/util"
)

func TestParseUploadAutoCompressesWithZstd(t *testing.T) {
	payload := bytes.Repeat([]byte("hello seaweedfs zstd default! "), 256)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "notes.txt")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	r := httptest.NewRequest("POST", "/3,01637037d6", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())

	pu, e := ParseUpload(r, 32*1024*1024, &bytes.Buffer{})
	if e != nil {
		t.Fatalf("ParseUpload: %v", e)
	}

	if !pu.IsZstd {
		t.Fatalf("expected compressable text upload to be auto-compressed with zstd, IsZstd=false IsGzipped=%v", pu.IsGzipped)
	}
	if !util.IsZstdContent(pu.Data) {
		t.Fatalf("stored payload is not zstd frames: first bytes % x", pu.Data[:4])
	}
	if pu.OriginalDataSize != len(payload) {
		t.Fatalf("OriginalDataSize = %d, want %d", pu.OriginalDataSize, len(payload))
	}
	decoded, err := util.DecompressData(pu.Data)
	if err != nil {
		t.Fatalf("DecompressData: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("round trip mismatch")
	}
}

func TestParseUploadRespectsIncomingZstdContentEncoding(t *testing.T) {
	payload, err := util.ZstdData(bytes.Repeat([]byte("already zstd "), 256))
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="file"; filename="notes.txt"`},
		"Content-Encoding":    {"zstd"},
	})
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	r := httptest.NewRequest("POST", "/3,01637037d6", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())

	pu, e := ParseUpload(r, 32*1024*1024, &bytes.Buffer{})
	if e != nil {
		t.Fatalf("ParseUpload: %v", e)
	}

	if !pu.IsZstd {
		t.Fatalf("expected Content-Encoding: zstd to be honored, IsZstd=false IsGzipped=%v", pu.IsGzipped)
	}
	if !bytes.Equal(pu.Data, payload) {
		t.Fatalf("zstd payload must be stored as-is, got %d bytes want %d", len(pu.Data), len(payload))
	}
	clear := bytes.Repeat([]byte("already zstd "), 256)
	if pu.OriginalDataSize != len(clear) {
		t.Fatalf("OriginalDataSize = %d, want %d", pu.OriginalDataSize, len(clear))
	}
}

func TestParseUploadReplicateSkipsRecompression(t *testing.T) {
	payload := bytes.Repeat([]byte("replica keeps my bytes "), 256)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "notes.txt")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	r := httptest.NewRequest("POST", "/3,01637037d6?type=replicate", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())

	pu, e := ParseUpload(r, 32*1024*1024, &bytes.Buffer{})
	if e != nil {
		t.Fatalf("ParseUpload: %v", e)
	}

	if pu.IsZstd || pu.IsGzipped {
		t.Fatalf("replicate upload must keep the source compression state, got IsZstd=%v IsGzipped=%v", pu.IsZstd, pu.IsGzipped)
	}
	if !bytes.Equal(pu.Data, payload) {
		t.Fatalf("replicate upload must not be recompressed")
	}
}

// buildMultipartUpload is a small helper assembling a multipart upload request
// the way clients send it to the volume server.
func buildMultipartUpload(t *testing.T, url, filename string, data []byte, partHeader textproto.MIMEHeader) *http.Request {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	h := textproto.MIMEHeader{"Content-Disposition": {`form-data; name="file"; filename="` + filename + `"`}}
	for k, v := range partHeader {
		h[k] = v
	}
	part, err := writer.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	r := httptest.NewRequest("POST", url, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	return r
}

func TestParseUploadSkipsIncompressibleContent(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	payload := make([]byte, 64*1024)
	rnd.Read(payload)

	rec := buildMultipartUpload(t, "/3,01637037d6", "random.txt", payload, nil)
	pu, e := ParseUpload(rec, 32*1024*1024, &bytes.Buffer{})
	if e != nil {
		t.Fatalf("ParseUpload: %v", e)
	}

	if pu.IsZstd || pu.IsGzipped {
		t.Fatalf("random bytes must not be force-compressed, got IsZstd=%v IsGzipped=%v", pu.IsZstd, pu.IsGzipped)
	}
	if !bytes.Equal(pu.Data, payload) {
		t.Fatalf("incompressible payload must be stored verbatim")
	}
	if pu.OriginalDataSize != len(payload) {
		t.Fatalf("OriginalDataSize = %d, want %d", pu.OriginalDataSize, len(payload))
	}
}

func TestParseUploadKeepsLegacyGzipIncoming(t *testing.T) {
	clear := bytes.Repeat([]byte("legacy gzip stays gzip "), 256)
	payload, err := util.GzipData(clear)
	if err != nil {
		t.Fatalf("GzipData: %v", err)
	}

	rec := buildMultipartUpload(t, "/3,01637037d6", "notes.txt", payload, textproto.MIMEHeader{"Content-Encoding": {"gzip"}})
	pu, e := ParseUpload(rec, 32*1024*1024, &bytes.Buffer{})
	if e != nil {
		t.Fatalf("ParseUpload: %v", e)
	}

	if !pu.IsGzipped || pu.IsZstd {
		t.Fatalf("incoming gzip must stay gzip, got IsGzipped=%v IsZstd=%v", pu.IsGzipped, pu.IsZstd)
	}
	if !util.IsGzippedContent(pu.Data) {
		t.Fatalf("gzip payload must be preserved verbatim")
	}
	if pu.OriginalDataSize != len(clear) {
		t.Fatalf("OriginalDataSize = %d, want %d", pu.OriginalDataSize, len(clear))
	}
}

func TestParseUploadZstdWithContentMd5(t *testing.T) {
	clear := bytes.Repeat([]byte("md5 over zstd! "), 512)
	payload, err := util.ZstdData(clear)
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}
	sum := md5.Sum(clear)
	valid := base64.StdEncoding.EncodeToString(sum[:])

	cases := []struct {
		name    string
		md5     string
		wantErr bool
	}{
		{name: "matching md5 of clear data", md5: valid},
		{name: "mismatching md5 fails", md5: base64.StdEncoding.EncodeToString(make([]byte, 16)), wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := buildMultipartUpload(t, "/3,01637037d6", "notes.txt", payload, textproto.MIMEHeader{
				"Content-Encoding": {"zstd"},
				"Content-MD5":      {c.md5},
			})
			pu, e := ParseUpload(rec, 32*1024*1024, &bytes.Buffer{})
			if c.wantErr {
				if e == nil {
					t.Fatalf("expected Content-MD5 mismatch error, got none")
				}
				return
			}
			if e != nil {
				t.Fatalf("ParseUpload: %v", e)
			}
			if pu.OriginalDataSize != len(clear) {
				t.Fatalf("OriginalDataSize = %d, want decompressed %d", pu.OriginalDataSize, len(clear))
			}
			if !bytes.Equal(pu.UncompressedData, clear) {
				t.Fatalf("UncompressedData must be the decompressed clear data for MD5 verification")
			}
			if !bytes.Equal(pu.Data, payload) {
				t.Fatalf("stored Data must remain the zstd frames")
			}
		})
	}
}

func TestParseUploadChunkManifestStaysRaw(t *testing.T) {
	payload := []byte(`{"chunks":[{"file_id":"1,abc","size":1024}]}`)

	rec := buildMultipartUpload(t, "/3,01637037d6?cm=true", "manifest", payload, nil)
	pu, e := ParseUpload(rec, 32*1024*1024, &bytes.Buffer{})
	if e != nil {
		t.Fatalf("ParseUpload: %v", e)
	}

	if pu.IsZstd || pu.IsGzipped {
		t.Fatalf("chunk manifest must never be recompressed, got IsZstd=%v IsGzipped=%v", pu.IsZstd, pu.IsGzipped)
	}
	if !bytes.Equal(pu.Data, payload) {
		t.Fatalf("chunk manifest must be stored verbatim")
	}
}

// TestParseUploadAnalyticsFormatsSkipCompression pins that already-compressed
// analytics files (parquet/orc/avro/...) are never probed or re-compressed.
func TestParseUploadAnalyticsFormatsSkipCompression(t *testing.T) {
	// parquet magic "PAR1" + binary column data (real parquet pages contain
	// binary bytes, which http.DetectContentType classifies as octet-stream —
	// that is the path where the extension skip list applies)
	payload := append([]byte("PAR1"),
		bytes.Repeat([]byte{0x00, 0x01, 0xFE, 0xFF, 0x0C, 'A'}, 512)...)

	for _, ext := range []string{".parquet", ".parq", ".orc", ".avro", ".arrow", ".feather", ".lance"} {
		t.Run(ext, func(t *testing.T) {
			rec := buildMultipartUpload(t, "/3,01637037d6", "table"+ext, payload, nil)
			pu, e := ParseUpload(rec, 32*1024*1024, &bytes.Buffer{})
			if e != nil {
				t.Fatalf("ParseUpload: %v", e)
			}
			if pu.IsZstd || pu.IsGzipped {
				t.Fatalf("%s payload must not be re-compressed", ext)
			}
			if !bytes.Equal(pu.Data, payload) {
				t.Fatalf("%s payload must be stored verbatim", ext)
			}
		})
	}
}
