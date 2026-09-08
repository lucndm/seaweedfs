package weed_server

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/seaweedfs/seaweedfs/weed/glog"
	"github.com/seaweedfs/seaweedfs/weed/util"
)

// Fork patch: zstd Content-Encoding negotiation on the filer read path.
//
// Uploads sent with "Content-Encoding: zstd" are stored verbatim as zstd
// frames (needle_parse_upload.go). Direct volume reads negotiate via
// volume_server_handlers_read.go, but the filer streams raw stored bytes, so
// zstd frames leaked to clients that never asked for them (S3 consumers,
// presigned URLs, rclone...). This wrapper peeks the first bytes of the body
// before anything reaches the wire, then either passes the frames through
// with "Content-Encoding: zstd" (client advertises support) or
// transparently stream-decompresses (plain clients).
//
// Ranged requests index the stored bytes, so the frames ARE the
// representation: every ranged response to a zstd-stored object carries the
// raw frames plus "Content-Encoding: zstd", advertised or not (mirrors S3,
// which returns Content-Encoding from object metadata regardless of
// Accept-Encoding). A client that cannot decode zstd therefore gets frames it
// can identify instead of silent garbage.
//
// The caller MUST invoke Finalize after ProcessRangeRequest returns — it is
// the end-of-body signal that lets bodies smaller than the peek window be
// classified and lets the pipe decoder flush its tail.

const zstdPeekLen = 4 // zstd frame magic: 28 B5 2F FD

type zstdAwareWriter struct {
	rw            http.ResponseWriter
	acceptsZstd   bool
	hasRange      bool
	buf           []byte
	decided       bool
	forwardedHead bool
	decode        bool
	pipeW         *io.PipeWriter
	pipeDone      chan struct{}
	pipeOnce      sync.Once
	finalOnce     sync.Once
}

func newZstdAwareWriter(rw http.ResponseWriter, r *http.Request) *zstdAwareWriter {
	return &zstdAwareWriter{
		rw:          rw,
		acceptsZstd: strings.Contains(r.Header.Get("Accept-Encoding"), "zstd"),
		hasRange:    r.Header.Get("Range") != "",
		buf:         make([]byte, 0, zstdPeekLen),
	}
}

// PreDecide flags the body as zstd-stored before any header is written.
// Ranged responses call WriteHeader(206) before streaming, so the peek flow
// cannot set headers in time; a caller that probed the stored head bytes
// (only worth doing for Range+Accept-Encoding: zstd requests) reports it here.
func (z *zstdAwareWriter) PreDecide(isZstd bool) {
	if z.decided {
		return
	}
	z.decided = true
	if !isZstd {
		return
	}
	h := z.rw.Header()
	h.Add("Vary", "Accept-Encoding")
	// The frames are the representation — always label them truthfully,
	// advertised or not (see the type comment).
	h.Set("Content-Encoding", "zstd")
	if !z.acceptsZstd {
		glog.V(1).Infof("filer zstd: ranged request on zstd-stored object without Accept-Encoding; serving frames with Content-Encoding: zstd")
	}
}

func (z *zstdAwareWriter) Header() http.Header {
	return z.rw.Header()
}

func (z *zstdAwareWriter) WriteHeader(code int) {
	if !z.decided && code != http.StatusOK && code != http.StatusPartialContent {
		// Error/redirect responses: never touch encoding headers. 200/206 are
		// left undecided so the body head can still be inspected.
		z.decide(nil)
	}
	z.rw.WriteHeader(code)
}

func (z *zstdAwareWriter) Write(p []byte) (int, error) {
	if !z.decided {
		if !z.hasRange && len(z.buf) < zstdPeekLen {
			need := zstdPeekLen - len(z.buf)
			if need > len(p) {
				z.buf = append(z.buf, p...)
				return len(p), nil
			}
			z.buf = append(z.buf, p[:need]...)
			p = p[need:]
		}
		z.decide(z.buf)
	}
	if z.decode {
		if z.pipeW == nil {
			return 0, io.ErrClosedPipe
		}
		return z.pipeW.Write(p)
	}
	if !z.forwardedHead {
		if _, err := z.rw.Write(z.buf); err != nil {
			return 0, err
		}
		z.forwardedHead = true
	}
	return z.rw.Write(p)
}

// Finalize classifies bodies smaller than the peek window and flushes the
// pipe decoder after the last body byte has been written.
func (z *zstdAwareWriter) Finalize() {
	z.finalOnce.Do(func() {
		if !z.decided {
			z.decide(z.buf)
		}
		if z.pipeW != nil {
			z.pipeW.Close()
			if z.pipeDone != nil {
				<-z.pipeDone
			}
		}
	})
}

// decide inspects the peeked head bytes and picks passthrough vs decode.
// head may be shorter than zstdPeekLen (tiny bodies, or unknown via
// WriteHeader on errors) — IsZstdContent returns false for those.
func (z *zstdAwareWriter) decide(head []byte) {
	if z.decided {
		return
	}
	z.decided = true
	if !util.IsZstdContent(head) {
		return
	}
	h := z.rw.Header()
	h.Add("Vary", "Accept-Encoding")
	switch {
	case z.hasRange:
		// Ranges index stored bytes; the frames are the representation —
		// label them truthfully even without advertisement (same policy as
		// PreDecide).
		h.Set("Content-Encoding", "zstd")
	default:
		if z.acceptsZstd {
			h.Set("Content-Encoding", "zstd")
			return
		}
		// Plain client: transparently decode. Body length differs from the
		// stored size, so the Content-Length header must go, and a
		// metadata-declared Content-Encoding no longer matches the body.
		h.Del("Content-Length")
		h.Del("Content-Encoding")
		pr, pw := io.Pipe()
		z.pipeW = pw
		z.pipeDone = make(chan struct{})
		z.decode = true
		go func() {
			defer z.pipeOnce.Do(func() { close(z.pipeDone) })
			if _, err := util.UnzstdStream(z.rw, pr); err != nil && err != io.EOF {
				// Headers and partial body are already on the wire; the
				// stream truncates. A corrupt stored frame surfaces here.
				glog.Errorf("filer zstd: stream decode failed: %v", err)
			}
		}()
		// The peeked head bytes were held back from the caller's stream;
		// the decoder needs them (the frame magic) to start decoding.
		if _, err := pw.Write(head); err != nil {
			glog.Errorf("filer zstd: feeding decoder head: %v", err)
		}
	}
}

var _ http.ResponseWriter = (*zstdAwareWriter)(nil)
