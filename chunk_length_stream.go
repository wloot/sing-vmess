package vmess

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/sha3"
)

var ErrBadLengthChunk = E.New("bad length chunk")

type StreamChunkReader struct {
	upstream      io.Reader
	chunkMasking  sha3.ShakeHash
	globalPadding sha3.ShakeHash
	header        [2]byte
}

func NewStreamChunkReader(upstream io.Reader, chunkMasking sha3.ShakeHash, globalPadding sha3.ShakeHash) *StreamChunkReader {
	return &StreamChunkReader{
		upstream:      upstream,
		chunkMasking:  chunkMasking,
		globalPadding: globalPadding,
	}
}

// readLength reads the length prefix of the next chunk and returns the payload
// and padding lengths it describes; a payload length of zero ends the stream.
func (r *StreamChunkReader) readLength() (dataLen int, paddingLen int, err error) {
	_, err = io.ReadFull(r.upstream, r.header[:])
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint16(r.header[:])
	if r.globalPadding != nil {
		var hashCode uint16
		common.Must(binary.Read(r.globalPadding, binary.BigEndian, &hashCode))
		paddingLen = int(hashCode % 64)
	}
	if r.chunkMasking != nil {
		var hashCode uint16
		common.Must(binary.Read(r.chunkMasking, binary.BigEndian, &hashCode))
		length ^= hashCode
	}
	dataLen = int(length) - paddingLen
	if dataLen < 0 {
		err = E.Extend(ErrBadLengthChunk, "length=", length, ", padding=", paddingLen)
	}
	return
}

func (r *StreamChunkReader) Read(p []byte) (n int, err error) {
	dataLen, paddingLen, err := r.readLength()
	if err != nil {
		return
	}
	if dataLen == 0 {
		err = io.EOF
		return
	}
	var readLen int
	readLen = len(p)
	if readLen > dataLen {
		readLen = dataLen
	} else if readLen < dataLen {
		return 0, E.Extend(io.ErrShortBuffer, "stream chunk need ", dataLen)
	}
	n, err = io.ReadFull(r.upstream, p[:readLen])
	if err != nil {
		return
	}
	_, err = io.CopyN(io.Discard, r.upstream, int64(paddingLen))
	return
}

// readChunk reads the next chunk into a buffer of its own, allocated once the
// length prefix says how much is coming, with the headroom the relay asked for.
func (r *StreamChunkReader) readChunk(frontHeadroom int, rearHeadroom int) (*buf.Buffer, error) {
	dataLen, paddingLen, err := r.readLength()
	if err != nil {
		return nil, err
	}
	if dataLen == 0 {
		return nil, io.EOF
	}
	buffer := buf.NewSize(frontHeadroom + dataLen + rearHeadroom)
	buffer.Resize(frontHeadroom, 0)
	_, err = buffer.ReadFullFrom(r.upstream, dataLen)
	if err == nil && paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r.upstream, int64(paddingLen))
	}
	if err != nil {
		buffer.Release()
		return nil, err
	}
	return buffer, nil
}

func (r *StreamChunkReader) Upstream() any {
	return r.upstream
}

type StreamChunkWriter struct {
	upstream      N.ExtendedWriter
	vectorised    N.VectorisedWriter
	chunkMasking  sha3.ShakeHash
	globalPadding sha3.ShakeHash
	hashAccess    sync.Mutex
	writeAccess   sync.Mutex
}

func NewStreamChunkWriter(upstream io.Writer, chunkMasking sha3.ShakeHash, globalPadding sha3.ShakeHash) *StreamChunkWriter {
	return &StreamChunkWriter{
		upstream:      bufio.NewExtendedWriter(upstream),
		chunkMasking:  chunkMasking,
		globalPadding: globalPadding,
	}
}

func (w *StreamChunkWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	dataLen := uint16(len(p))
	var paddingLen uint16
	if w.globalPadding != nil || w.chunkMasking != nil {
		w.hashAccess.Lock()
		if w.globalPadding != nil {
			var hashCode uint16
			common.Must(binary.Read(w.globalPadding, binary.BigEndian, &hashCode))
			paddingLen = hashCode % MaxPaddingSize
			dataLen += paddingLen
		}
		if w.chunkMasking != nil {
			var hashCode uint16
			common.Must(binary.Read(w.chunkMasking, binary.BigEndian, &hashCode))
			dataLen ^= hashCode
		}
		w.hashAccess.Unlock()
	}
	w.writeAccess.Lock()
	err = binary.Write(w.upstream, binary.BigEndian, dataLen)
	if err != nil {
		return
	}
	n, err = w.upstream.Write(p)
	if err != nil {
		return
	}
	if paddingLen > 0 {
		_, err = io.CopyN(w.upstream, rand.Reader, int64(paddingLen))
		if err != nil {
			return
		}
	}
	w.writeAccess.Unlock()
	return
}

func (w *StreamChunkWriter) WriteBuffer(buffer *buf.Buffer) error {
	if buffer.IsEmpty() {
		buffer.Release()
		return nil
	}
	err := w.frame(buffer)
	if err != nil {
		buffer.Release()
		return err
	}
	return w.upstream.WriteBuffer(buffer)
}

// CreateVectorisedWriter reports whether a batch handed to this writer reaches
// the socket as one writev, and prepares the way down if so. Connections that
// never write in batches allocate nothing for it.
func (w *StreamChunkWriter) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	if w.vectorised == nil {
		vectorised, created := bufio.CreateVectorisedWriter(w.upstream)
		if !created {
			return nil, false
		}
		w.vectorised = vectorised
	}
	return w, true
}

// WriteVectorised frames every buffer in place and hands the batch down in
// one call. Empty buffers are dropped: a zero-length chunk ends the stream.
// Without a socket underneath it is one write per buffer.
func (w *StreamChunkWriter) WriteVectorised(buffers []*buf.Buffer) error {
	if w.vectorised == nil {
		if _, created := w.CreateVectorisedWriter(); !created {
			return writeBuffers(w, buffers)
		}
	}
	chunks := buffers[:0]
	for _, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		err := w.frame(buffer)
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
		chunks = append(chunks, buffer)
	}
	if len(chunks) == 0 {
		return nil
	}
	return w.vectorised.WriteVectorised(chunks)
}

// frame prepends the (masked) length and appends the padding of one chunk in
// place, using the buffer's headroom. The buffer must not be empty.
func (w *StreamChunkWriter) frame(buffer *buf.Buffer) error {
	dataLen := uint16(buffer.Len())
	var paddingLen uint16
	if w.globalPadding != nil || w.chunkMasking != nil {
		w.hashAccess.Lock()
		if w.globalPadding != nil {
			var hashCode uint16
			common.Must(binary.Read(w.globalPadding, binary.BigEndian, &hashCode))
			paddingLen = hashCode % MaxPaddingSize
			dataLen += paddingLen
		}
		if w.chunkMasking != nil {
			var hashCode uint16
			common.Must(binary.Read(w.chunkMasking, binary.BigEndian, &hashCode))
			dataLen ^= hashCode
		}
		w.hashAccess.Unlock()
	}
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), dataLen)
	if paddingLen > 0 {
		_, err := buffer.ReadFullFrom(rand.Reader, int(paddingLen))
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *StreamChunkWriter) WriteWithChecksum(checksum uint32, p []byte) (n int, err error) {
	dataLen := uint16(4 + len(p))
	var paddingLen uint16
	if w.globalPadding != nil || w.chunkMasking != nil {
		w.hashAccess.Lock()
		if w.globalPadding != nil {
			var hashCode uint16
			common.Must(binary.Read(w.globalPadding, binary.BigEndian, &hashCode))
			paddingLen = hashCode % MaxPaddingSize
			dataLen += paddingLen
		}
		if w.chunkMasking != nil {
			var hashCode uint16
			common.Must(binary.Read(w.chunkMasking, binary.BigEndian, &hashCode))
			dataLen ^= hashCode
		}
		w.hashAccess.Unlock()
	}
	w.writeAccess.Lock()
	err = binary.Write(w.upstream, binary.BigEndian, dataLen)
	if err != nil {
		return
	}
	err = binary.Write(w.upstream, binary.BigEndian, checksum)
	if err != nil {
		return
	}
	n, err = w.upstream.Write(p)
	if err != nil {
		return
	}
	if paddingLen > 0 {
		_, err = io.CopyN(w.upstream, rand.Reader, int64(paddingLen))
		if err != nil {
			return
		}
	}
	w.writeAccess.Unlock()
	return
}

func (w *StreamChunkWriter) FrontHeadroom() int {
	return 2
}

func (w *StreamChunkWriter) RearHeadroom() int {
	if w.globalPadding != nil {
		return MaxPaddingSize
	} else {
		return 0
	}
}

func (w *StreamChunkWriter) Upstream() any {
	return w.upstream
}
