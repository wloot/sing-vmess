package vmess

import (
	"io"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// chunkBufferReader is a layer of a chunk stream read chain that can read the
// next chunk into a buffer of its own, laid out the way the relay wants it.
type chunkBufferReader interface {
	io.Reader
	readChunk(frontHeadroom int, rearHeadroom int) (*buf.Buffer, error)
}

// chunkReader sits on top of a chunk stream read chain on the server. A relay
// that waits for buffers gets every chunk in a buffer allocated only once its
// length has arrived, so an idle connection holds no read buffer at all. Plain
// reads that ask for less than a chunk keep the rest for the next call, like
// bufio.ChunkReader, but a read that can take a whole chunk goes straight to
// the chain and nothing is kept around for the life of the connection.
//
// There is deliberately no Close: the connection may be closed from another
// goroutine while the reader is handing its leftover out, so the leftover is
// left to the garbage collector rather than returned to the pool.
type chunkReader struct {
	upstream chunkBufferReader
	extended N.ExtendedReader
	cache    *buf.Buffer
	options  N.ReadWaitOptions
}

// newChunkReader wraps a CreateReader chain for the server side, falling back
// to bufio.ChunkReader for the legacy stream, whose checksum layer cannot hand
// out chunks.
func newChunkReader(upstream io.Reader) io.Reader {
	switch reader := upstream.(type) {
	case *AEADReader:
		if reader.chunks != nil {
			return &chunkReader{upstream: reader, extended: reader}
		}
	case *StreamChunkReader, *AEADChunkReader:
		return &chunkReader{upstream: reader.(chunkBufferReader), extended: bufio.NewExtendedReader(upstream)}
	}
	return bufio.NewChunkReader(upstream, ReadChunkSize)
}

func (r *chunkReader) Read(p []byte) (n int, err error) {
	if r.cache != nil {
		return r.readCache(p)
	}
	if len(p) >= ReadChunkSize {
		return r.upstream.Read(p)
	}
	chunk, err := r.upstream.readChunk(0, 0)
	if err != nil {
		return
	}
	r.cache = chunk
	return r.readCache(p)
}

func (r *chunkReader) readCache(p []byte) (n int, err error) {
	n = copy(p, r.cache.Bytes())
	r.cache.Advance(n)
	if r.cache.IsEmpty() {
		r.cache.Release()
		r.cache = nil
	}
	return
}

func (r *chunkReader) ReadBuffer(buffer *buf.Buffer) error {
	if r.cache != nil {
		return r.readCacheBuffer(buffer)
	}
	if buffer.FreeLen() >= ReadChunkSize {
		return r.extended.ReadBuffer(buffer)
	}
	chunk, err := r.upstream.readChunk(0, 0)
	if err != nil {
		return err
	}
	r.cache = chunk
	return r.readCacheBuffer(buffer)
}

func (r *chunkReader) readCacheBuffer(buffer *buf.Buffer) error {
	n, _ := buffer.Write(r.cache.Bytes())
	r.cache.Advance(n)
	if r.cache.IsEmpty() {
		r.cache.Release()
		r.cache = nil
	}
	return nil
}

func (r *chunkReader) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	r.options = options
	return false
}

func (r *chunkReader) WaitReadBuffer() (*buf.Buffer, error) {
	if r.cache == nil {
		return r.upstream.readChunk(r.options.FrontHeadroom, r.options.RearHeadroom)
	}
	buffer := r.cache
	r.cache = nil
	if buffer.Start() >= r.options.FrontHeadroom && buffer.FreeLen() >= r.options.RearHeadroom {
		return buffer, nil
	}
	relayout := buf.NewSize(r.options.FrontHeadroom + buffer.Len() + r.options.RearHeadroom)
	relayout.Resize(r.options.FrontHeadroom, 0)
	relayout.Write(buffer.Bytes())
	buffer.Release()
	return relayout, nil
}

var _ N.ReadWaiter = (*chunkReader)(nil)
