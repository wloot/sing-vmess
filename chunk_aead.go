package vmess

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type AEADReader struct {
	upstream   N.ExtendedReader
	chunks     chunkBufferReader // upstream again, when it can hand out whole chunks
	cipher     cipher.AEAD
	nonce      []byte
	nonceCount uint16
}

func NewAEADReader(upstream io.Reader, cipher cipher.AEAD, nonce []byte) *AEADReader {
	readNonce := make([]byte, cipher.NonceSize())
	copy(readNonce, nonce)
	chunks, _ := upstream.(chunkBufferReader)
	return &AEADReader{
		upstream: bufio.NewExtendedReader(upstream),
		chunks:   chunks,
		cipher:   cipher,
		nonce:    readNonce,
	}
}

func NewAes128GcmReader(upstream io.Reader, key []byte, nonce []byte) *AEADReader {
	return NewAEADReader(upstream, newAesGcm(key), nonce)
}

func NewChacha20Poly1305Reader(upstream io.Reader, key []byte, nonce []byte) *AEADReader {
	return NewAEADReader(upstream, newChacha20Poly1305(GenerateChacha20Poly1305Key(key)), nonce)
}

func (r *AEADReader) Read(p []byte) (n int, err error) {
	n, err = r.upstream.Read(p)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(r.nonce, r.nonceCount)
	r.nonceCount += 1
	_, err = r.cipher.Open(p[:0], r.nonce, p[:n], nil)
	if err != nil {
		return
	}
	n -= CipherOverhead
	return
}

func (r *AEADReader) ReadBuffer(buffer *buf.Buffer) error {
	err := r.upstream.ReadBuffer(buffer)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(r.nonce, r.nonceCount)
	r.nonceCount += 1
	_, err = r.cipher.Open(buffer.Index(0), r.nonce, buffer.Bytes(), nil)
	if err != nil {
		return err
	}
	buffer.Truncate(buffer.Len() - CipherOverhead)
	return nil
}

// readChunk takes the next chunk from the length layer and opens it in place.
func (r *AEADReader) readChunk(frontHeadroom int, rearHeadroom int) (*buf.Buffer, error) {
	buffer, err := r.chunks.readChunk(frontHeadroom, rearHeadroom)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(r.nonce, r.nonceCount)
	r.nonceCount += 1
	_, err = r.cipher.Open(buffer.Index(0), r.nonce, buffer.Bytes(), nil)
	if err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.Truncate(buffer.Len() - CipherOverhead)
	return buffer, nil
}

func (r *AEADReader) Upstream() any {
	return r.upstream
}

type AEADWriter struct {
	upstream   N.ExtendedWriter
	vectorised N.VectorisedWriter
	cipher     cipher.AEAD
	nonce      []byte
	nonceCount uint16
}

func NewAEADWriter(upstream io.Writer, cipher cipher.AEAD, nonce []byte) *AEADWriter {
	writeNonce := make([]byte, cipher.NonceSize())
	copy(writeNonce, nonce)
	return &AEADWriter{
		upstream: bufio.NewExtendedWriter(upstream),
		cipher:   cipher,
		nonce:    writeNonce,
	}
}

func NewAes128GcmWriter(upstream io.Writer, key []byte, nonce []byte) *AEADWriter {
	return NewAEADWriter(upstream, newAesGcm(key), nonce)
}

func NewChacha20Poly1305Writer(upstream io.Writer, key []byte, nonce []byte) *AEADWriter {
	return NewAEADWriter(upstream, newChacha20Poly1305(GenerateChacha20Poly1305Key(key)), nonce)
}

func (w *AEADWriter) Write(p []byte) (n int, err error) {
	// TODO: fix stack buffer
	return bufio.WriteBuffer(w, buf.As(p))
	/*_buffer := buf.StackNewSize(len(p) + CipherOverhead)
	defer common.KeepAlive(_buffer)
	buffer := _buffer
	defer buffer.Release()
	binary.BigEndian.PutUint16(w.nonce, w.nonceCount)
	w.nonceCount += 1
	w.cipher.Seal(buffer.Index(0), w.nonce, p, nil)
	buffer.Truncate(buffer.FreeLen())
	_, err = w.upstream.Write(buffer.Bytes())
	if err == nil {
		n = len(p)
	}
	return*/
}

func (w *AEADWriter) WriteBuffer(buffer *buf.Buffer) error {
	if buffer.IsEmpty() {
		buffer.Release()
		return nil
	}
	w.seal(buffer)
	return w.upstream.WriteBuffer(buffer)
}

// CreateVectorisedWriter reports whether a batch handed to this writer reaches
// the socket as one writev, and prepares the way down if so. Connections that
// never write in batches allocate nothing for it.
func (w *AEADWriter) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	if w.vectorised == nil {
		vectorised, created := bufio.CreateVectorisedWriter(w.upstream)
		if !created {
			return nil, false
		}
		w.vectorised = vectorised
	}
	return w, true
}

// WriteVectorised seals every buffer in place and hands the whole batch down
// in one call, so a burst of chunks reaches the socket as a single writev
// instead of one write per chunk. Without a socket underneath it is one write
// per buffer, which is what the batch would have cost anyway.
func (w *AEADWriter) WriteVectorised(buffers []*buf.Buffer) error {
	if w.vectorised == nil {
		if _, created := w.CreateVectorisedWriter(); !created {
			return writeBuffers(w, buffers)
		}
	}
	for _, buffer := range buffers {
		w.seal(buffer)
	}
	return w.vectorised.WriteVectorised(buffers)
}

// seal encrypts the buffer in place; the tag goes into its rear headroom.
func (w *AEADWriter) seal(buffer *buf.Buffer) {
	binary.BigEndian.PutUint16(w.nonce, w.nonceCount)
	w.nonceCount += 1
	w.cipher.Seal(buffer.Index(0), w.nonce, buffer.Bytes(), nil)
	buffer.Extend(CipherOverhead)
}

func (w *AEADWriter) RearHeadroom() int {
	return CipherOverhead
}

func (w *AEADWriter) Upstream() any {
	return w.upstream
}
