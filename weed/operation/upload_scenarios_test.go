package operation

import (
	"bytes"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/storage/needle"
	"github.com/seaweedfs/seaweedfs/weed/util"
)

// captureNeedle spins up an httptest server that mimics the volume server
// write path: it runs the real needle.CreateNeedleFromRequest (which calls
// ParseUpload, applies server-side auto-compression and builds the on-disk
// needle), then records the needle for assertions.
func captureNeedle(t *testing.T) (uploader *Uploader, targetUrl func(query string) string, captured **needle.Needle, originalSize *int) {
	t.Helper()
	captured, originalSize = new(*needle.Needle), new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, size, _, err := needle.CreateNeedleFromRequest(r, false, 32*1024*1024, &bytes.Buffer{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		*captured, *originalSize = n, size
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"x","size":1}`))
	}))
	t.Cleanup(server.Close)
	return newUploader(server.Client()), func(query string) string { return server.URL + "/3,01637037d6" + query }, captured, originalSize
}

// TestUploadScenariosEndToEnd drives the full client-side decision chain
// (doUploadData: detect mime → decide compression → zstd → wire headers)
// against a stand-in volume running the real needle parsing, covering the
// scenarios uploads hit in production.
func TestUploadScenariosEndToEnd(t *testing.T) {
	rnd := rand.New(rand.NewSource(42))
	random64k := make([]byte, 64*1024)
	rnd.Read(random64k)

	clearText := bytes.Repeat([]byte("seaweedfs zstd end to end! "), 1024) // ~27 KiB compressable

	cases := []struct {
		name string
		data []byte
		opt  UploadOption

		wantNeedleCompressed bool
		wantNeedleZstd       bool
		wantDataEqual        bool // needle data must equal the input verbatim
		wantOriginalSize     int  // 0 = expect len(clear input)
	}{
		{
			name:                 "compressable text becomes zstd",
			data:                 clearText,
			opt:                  UploadOption{Filename: "notes.txt", MimeType: "text/plain"},
			wantNeedleCompressed: true,
			wantNeedleZstd:       true,
		},
		{
			name:             "random bytes with unknown mime stay raw",
			data:             random64k,
			opt:              UploadOption{Filename: "blob"},
			wantNeedleZstd:   false,
			wantDataEqual:    true,
			wantOriginalSize: len(random64k),
		},
		{
			name:                 "highly compressible unknown mime is probed into zstd",
			data:                 bytes.Repeat([]byte{0}, 64*1024),
			opt:                  UploadOption{Filename: "blob"},
			wantNeedleCompressed: true,
			wantNeedleZstd:       true,
		},
		{
			name:             "jpeg payload is never recompressed",
			data:             random64k,
			opt:              UploadOption{Filename: "pic.jpg", MimeType: "image/jpeg"},
			wantDataEqual:    true,
			wantOriginalSize: len(random64k),
		},
		{
			name:             "zip payload is never recompressed",
			data:             random64k,
			opt:              UploadOption{Filename: "a.zip", MimeType: "application/zip"},
			wantDataEqual:    true,
			wantOriginalSize: len(random64k),
		},
		{
			name:             "tiny payload gains nothing and stays raw",
			data:             []byte("hello"),
			opt:              UploadOption{Filename: "hi.txt", MimeType: "text/plain"},
			wantDataEqual:    true,
			wantOriginalSize: 5,
		},
		{
			name:                 "replication forwards zstd needle untouched",
			data:                 mustZstd(t, clearText),
			opt:                  UploadOption{Filename: "notes.txt", MimeType: "text/plain", IsInputCompressed: true, IsReplication: true},
			wantNeedleCompressed: true,
			wantNeedleZstd:       true,
			wantOriginalSize:     len(clearText),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			uploader, targetUrl, n, originalSize := captureNeedle(t)
			query := ""
			if c.opt.IsReplication {
				query = "?type=replicate"
			}
			upResult, err := uploader.UploadData(t.Context(), c.data, func() *UploadOption {
				o := c.opt
				o.UploadUrl = targetUrl(query)
				return &o
			}())
			if err != nil {
				t.Fatalf("UploadData: %v", err)
			}
			if upResult == nil || upResult.Error != "" {
				t.Fatalf("bad upload result: %#v", upResult)
			}

			if (*n).IsCompressed() != c.wantNeedleCompressed {
				t.Fatalf("needle.IsCompressed = %v, want %v", (*n).IsCompressed(), c.wantNeedleCompressed)
			}
			if c.wantNeedleZstd && !util.IsZstdContent((*n).Data) {
				t.Fatalf("needle data is not zstd frames: % x", (*n).Data[:4])
			}
			if !c.wantNeedleZstd && c.wantDataEqual && !bytes.Equal((*n).Data, c.data) {
				t.Fatalf("needle data must be stored verbatim, got %d bytes want %d", len((*n).Data), len(c.data))
			}
			wantSize := c.wantOriginalSize
			if wantSize == 0 {
				wantSize = len(c.data)
			}
			if *originalSize != wantSize {
				t.Fatalf("originalSize = %d, want %d", *originalSize, wantSize)
			}

			// compressed needles must round-trip back to the clear input;
			// raw needles are already asserted verbatim above
			if !(*n).IsCompressed() {
				return
			}
			stored, err := util.DecompressData((*n).Data)
			if err != nil {
				t.Fatalf("DecompressData(stored): %v", err)
			}
			wantClear := c.data
			if c.opt.IsInputCompressed {
				wantClear, _ = util.DecompressData(c.data)
			}
			if !bytes.Equal(stored, wantClear) {
				t.Fatalf("round trip mismatch: got %d bytes, want %d", len(stored), len(wantClear))
			}
		})
	}
}

// TestUploadCipherKeepsZstdUnderEncryption verifies the encrypt(compress(data))
// ordering: a ciphered upload of compressable text stores ciphertext whose
// decryption is a zstd frame of the clear data.
func TestUploadCipherKeepsZstdUnderEncryption(t *testing.T) {
	uploader, targetUrl, n, _ := captureNeedle(t)
	clear := bytes.Repeat([]byte("cipher over zstd! "), 1024)

	upResult, err := uploader.UploadData(t.Context(), clear, &UploadOption{
		UploadUrl: targetUrl(""),
		Filename:  "secret.txt",
		MimeType:  "text/plain",
		Cipher:    true,
	})
	if err != nil {
		t.Fatalf("UploadData: %v", err)
	}
	if upResult.CipherKey == nil {
		t.Fatalf("expected cipher key on ciphered upload")
	}
	if upResult.Gzip != 1 {
		t.Fatalf("result.Gzip = %d, want 1 (plaintext was compressable)", upResult.Gzip)
	}

	decrypted, err := util.Decrypt((*n).Data, upResult.CipherKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !util.IsZstdContent(decrypted) {
		t.Fatalf("decrypted payload is not zstd frames: % x", decrypted[:4])
	}
	roundTrip, err := util.DecompressData(decrypted)
	if err != nil {
		t.Fatalf("DecompressData: %v", err)
	}
	if !bytes.Equal(roundTrip, clear) {
		t.Fatalf("cipher+zstd round trip mismatch")
	}
}

func mustZstd(t *testing.T, data []byte) []byte {
	t.Helper()
	z, err := util.ZstdData(data)
	if err != nil {
		t.Fatalf("ZstdData: %v", err)
	}
	return z
}
