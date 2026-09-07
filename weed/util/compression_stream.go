package util

import (
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	gzipReaderPool = sync.Pool{
		New: func() interface{} {
			return new(gzip.Reader)
			//return gzip.NewReader()
		},
	}

	gzipWriterPool = sync.Pool{
		New: func() interface{} {
			w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
			return w
		},
	}

	zstdReaderPool = sync.Pool{
		New: func() interface{} {
			d, _ := zstd.NewReader(nil)
			return d
		},
	}
)

func GzipStream(w io.Writer, r io.Reader) (int64, error) {
	gw, ok := gzipWriterPool.Get().(*gzip.Writer)
	if !ok {
		return 0, fmt.Errorf("gzip: new writer error")
	}
	gw.Reset(w)
	defer func() {
		gw.Close()
		gzipWriterPool.Put(gw)
	}()
	return io.Copy(gw, r)
}

func GunzipStream(w io.Writer, r io.Reader) (int64, error) {
	gr, ok := gzipReaderPool.Get().(*gzip.Reader)
	if !ok {
		return 0, fmt.Errorf("gzip: new reader error")
	}

	if err := gr.Reset(r); err != nil {
		return 0, err
	}
	defer func() {
		gr.Close()
		gzipReaderPool.Put(gr)
	}()
	return io.Copy(w, gr)
}

func UnzstdStream(w io.Writer, r io.Reader) (int64, error) {
	zr, ok := zstdReaderPool.Get().(*zstd.Decoder)
	if !ok {
		return 0, fmt.Errorf("zstd: new reader error")
	}
	if err := zr.Reset(r); err != nil {
		return 0, err
	}
	defer func() {
		zr.Reset(nil)
		zstdReaderPool.Put(zr)
	}()
	return io.Copy(w, zr)
}

// GetPooledZstdDecoder checks out a pooled zstd decoder wired to r. The
// returned decoder streams decompressed bytes; release it with
// PutPooledZstdDecoder. Used by chunk fetches that pass zstd through
// Accept-Encoding negotiation and must decode the response body.
func GetPooledZstdDecoder(r io.Reader) (*zstd.Decoder, error) {
	zr, ok := zstdReaderPool.Get().(*zstd.Decoder)
	if !ok {
		var err error
		zr, err = zstd.NewReader(nil)
		if err != nil {
			return nil, err
		}
	}
	if err := zr.Reset(r); err != nil {
		zstdReaderPool.Put(zr)
		return nil, err
	}
	return zr, nil
}

// PutPooledZstdDecoder returns a decoder to the pool. Safe to call at any
// point of the stream; Reset(nil) drops whatever decode state is left.
func PutPooledZstdDecoder(zr *zstd.Decoder) {
	zr.Reset(nil)
	zstdReaderPool.Put(zr)
}
