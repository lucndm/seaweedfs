package operation

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/util"
)

// captureUploadPart spins up an httptest volume stand-in that records the
// multipart part's Content-Encoding header and payload, then returns a
// uploader pointed at it.
func captureUploadPart(t *testing.T) (uploader *Uploader, targetUrl string, encoding *string, payload *[]byte) {
	t.Helper()
	encoding, payload = new(string), new([]byte)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		*encoding = part.Header.Get("Content-Encoding")
		partBody, err := io.ReadAll(part)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		*payload = partBody
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"x","size":1}`))
	}))
	t.Cleanup(server.Close)
	return newUploader(server.Client()), server.URL + "/3,01637037d6", encoding, payload
}

func TestUploadDataAutoCompressesWithZstd(t *testing.T) {
	uploader, targetUrl, encoding, payload := captureUploadPart(t)
	data := bytes.Repeat([]byte("hello seaweedfs zstd default! "), 256)

	result, err := uploader.UploadData(t.Context(), data, &UploadOption{
		UploadUrl: targetUrl,
		Filename:  "notes.txt",
		MimeType:  "text/plain",
	})
	if err != nil {
		t.Fatalf("UploadData: %v", err)
	}

	if *encoding != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd (zstd must be the default upload compression)", *encoding)
	}
	if !util.IsZstdContent(*payload) {
		t.Fatalf("uploaded payload is not zstd frames: % x", (*payload)[:4])
	}
	if result.Gzip != 1 {
		t.Fatalf("result.Gzip = %d, want 1", result.Gzip)
	}
	if result.Size != uint32(len(data)) {
		t.Fatalf("result.Size = %d, want clear size %d", result.Size, len(data))
	}
}

func TestUploadDataSniffsCompressionAlgorithmOfCompressedInput(t *testing.T) {
	clear := bytes.Repeat([]byte("sniff my magic bytes! "), 256)
	gzipData, _ := util.GzipData(clear)
	zstdData, _ := util.ZstdData(clear)

	cases := []struct {
		name          string
		data          []byte
		optionEnc     string
		wantHeaderEnc string
	}{
		{name: "gzip input without explicit encoding", data: gzipData, optionEnc: "", wantHeaderEnc: "gzip"},
		{name: "zstd input without explicit encoding", data: zstdData, optionEnc: "", wantHeaderEnc: "zstd"},
		{name: "explicit encoding wins over sniffing", data: zstdData, optionEnc: "gzip", wantHeaderEnc: "gzip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			uploader, targetUrl, encoding, payload := captureUploadPart(t)

			_, err := uploader.UploadData(t.Context(), c.data, &UploadOption{
				UploadUrl:         targetUrl,
				Filename:          "notes.txt",
				IsInputCompressed: true,
				ContentEncoding:   c.optionEnc,
			})
			if err != nil {
				t.Fatalf("UploadData: %v", err)
			}

			if *encoding != c.wantHeaderEnc {
				t.Fatalf("Content-Encoding = %q, want %q", *encoding, c.wantHeaderEnc)
			}
			if !bytes.Equal(*payload, c.data) {
				t.Fatalf("compressed input must be forwarded untouched")
			}
		})
	}
}
