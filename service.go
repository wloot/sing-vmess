package vmess

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/replay"
	"github.com/sagernet/sing/common/rw"

	"github.com/gofrs/uuid/v5"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

var (
	ErrBadHeader    = E.New("bad header")
	ErrBadTimestamp = E.New("bad timestamp")
	ErrReplay       = E.New("replayed request")
	ErrBadRequest   = E.New("bad request")
	ErrBadVersion   = E.New("bad version")
)

type Service[U comparable] struct {
	users                atomic.Pointer[userTable[U]] // immutable snapshot, see publishUsers
	replayFilter         replay.Filter
	handler              Handler
	time                 func() time.Time
	disableHeaderProtect bool
	alterIds             map[U][][16]byte
	alterIdUpdateTime    map[U]int64
	alterIdMap           map[[16]byte]legacyUserEntry[U]
	alterIdUpdateTask    *time.Ticker
	alterIdUpdateDone    chan struct{}
}

// userTable is the immutable snapshot NewConnection authenticates against. It
// is replaced wholesale and nothing here takes a lock: UpdateUsers publishes
// new credentials and promoteUser swaps in a snapshot with one more hot user.
type userTable[U comparable] struct {
	key      map[U][16]byte
	idCipher map[U]cipher.Block
	// hot holds the users that authenticated within authHotIdleSeconds and is
	// probed first. lastAccess is the only mutable field; it is updated
	// atomically in place, everything else is copied into the next snapshot.
	hot []authEntry[U]
	// cold holds every user, contiguous, and is only built by publishUsers, so
	// promoting a user costs a copy of hot and nothing proportional to the
	// user count. A miss on hot costs one sequential pass over it.
	cold []authEntry[U]
}

type authEntry[U comparable] struct {
	// lastAccess comes first so it stays 64-bit aligned for the atomic ops on
	// 32-bit targets; unix seconds, hot entries only.
	lastAccess int64
	user       U
	cipher     cipher.Block
}

type legacyUserEntry[U comparable] struct {
	User  U
	Time  int64
	Index int
}

// authHotIdleSeconds demotes a hot user that has not authenticated for this
// long, which is what bounds the hot slice: it never holds more than the users
// active in one such window. Demotion runs when a snapshot is rebuilt, not on
// the read path.
const authHotIdleSeconds = 600

func NewService[U comparable](handler Handler, options ...ServiceOption) *Service[U] {
	service := &Service[U]{
		// The timestamp check below accepts a whole-second offset of up to 120,
		// so a captured authID stays acceptable for slightly more than 240s of
		// wall time. Remembering it for less than that leaves a window in which
		// the filter has forgotten the authID while the timestamp still passes.
		replayFilter: replay.NewSimple(time.Second * 241),
		handler:      handler,
		time:         time.Now,
	}
	anyService := (*Service[string])(unsafe.Pointer(service))
	for _, option := range options {
		option(anyService)
	}
	return service
}

func (s *Service[U]) UpdateUsers(userList []U, userIdList []string, alterIdList []int) error {
	userKeyMap := make(map[U][16]byte)
	userIdCipherMap := make(map[U]cipher.Block)
	userAlterIds := make(map[U][][16]byte)
	for i, user := range userList {
		userId := userIdList[i]
		userUUID, err := uuid.FromString(userId)
		if err != nil {
			userUUID = uuid.NewV5(uuid.Nil, userId)
		}
		userCmdKey := Key(userUUID)
		userKeyMap[user] = userCmdKey
		userIdCipher, err := aes.NewCipher(KDF(userCmdKey[:], KDFSaltConstAuthIDEncryptionKey)[:16])
		if err != nil {
			return err
		}
		userIdCipherMap[user] = userIdCipher
		alterId := alterIdList[i]
		if alterId > 0 {
			alterIds := make([][16]byte, 0, alterId)
			currentId := userUUID
			for j := 0; j < alterId; j++ {
				currentId = AlterId(currentId)
				alterIds = append(alterIds, currentId)
			}
			userAlterIds[user] = alterIds
		}
	}
	s.publishUsers(userKeyMap, userIdCipherMap)
	s.alterIds = userAlterIds
	s.alterIdUpdateTime = make(map[U]int64)
	s.generateLegacyKeys()
	return nil
}

func (s *Service[U]) Start() error {
	const updateInterval = 10 * time.Second
	if len(s.alterIds) > 0 {
		s.alterIdUpdateTask = time.NewTicker(updateInterval)
		s.alterIdUpdateDone = make(chan struct{})
		go s.loopGenerateLegacyKeys()
	}
	return nil
}

func (s *Service[U]) Close() error {
	if s.alterIdUpdateTask != nil {
		s.alterIdUpdateTask.Stop()
		close(s.alterIdUpdateDone)
	}
	return nil
}

func (s *Service[U]) loopGenerateLegacyKeys() {
	for {
		select {
		case <-s.alterIdUpdateDone:
			return
		case <-s.alterIdUpdateTask.C:
		}
		s.generateLegacyKeys()
	}
}

func (s *Service[U]) generateLegacyKeys() {
	nowSec := s.time().Unix()
	endSec := nowSec + CacheDurationSeconds
	var hashValue [16]byte

	userAlterIdMap := make(map[[16]byte]legacyUserEntry[U])
	userAlterIdUpdateTime := make(map[U]int64)

	for user, alterIds := range s.alterIds {
		beginSec := s.alterIdUpdateTime[user]
		if beginSec < nowSec-CacheDurationSeconds {
			beginSec = nowSec - CacheDurationSeconds
		}
		for i, alterId := range alterIds {
			idHash := hmac.New(md5.New, alterId[:])
			for ts := beginSec; ts <= endSec; ts++ {
				common.Must(binary.Write(idHash, binary.BigEndian, uint64(ts)))
				idHash.Sum(hashValue[:0])
				idHash.Reset()
				userAlterIdMap[hashValue] = legacyUserEntry[U]{user, ts, i}
			}
		}
		userAlterIdUpdateTime[user] = nowSec
	}
	s.alterIdUpdateTime = userAlterIdUpdateTime
	s.alterIdMap = userAlterIdMap
}

// publishUsers installs new credentials. Users that are still present and not
// idle keep their place in hot, with the cipher re-derived from the new table
// and lastAccess carried over. A promotion that races with this store is
// lost, which only means that user is promoted again on its next cold hit.
func (s *Service[U]) publishUsers(key map[U][16]byte, idCipher map[U]cipher.Block) {
	var hot []authEntry[U]
	if current := s.users.Load(); current != nil {
		now := s.time().Unix()
		hot = make([]authEntry[U], 0, len(current.hot))
		for i := range current.hot {
			entry := &current.hot[i]
			currentCipher, loaded := idCipher[entry.user]
			if !loaded {
				continue
			}
			lastAccess := atomic.LoadInt64(&entry.lastAccess)
			if now-lastAccess > authHotIdleSeconds {
				continue
			}
			hot = append(hot, authEntry[U]{user: entry.user, cipher: currentCipher, lastAccess: lastAccess})
		}
	}
	cold := make([]authEntry[U], 0, len(idCipher))
	for user, userIdCipher := range idCipher {
		cold = append(cold, authEntry[U]{user: user, cipher: userIdCipher})
	}
	s.users.Store(&userTable[U]{key: key, idCipher: idCipher, hot: hot, cold: cold})
}

// promoteUser moves a user that just passed the cold scan into hot. It builds
// the next snapshot from the current one and swaps it in with a single
// compare-and-swap; if another promotion or an UpdateUsers landed first the
// attempt is simply dropped and the user is promoted on its next cold hit, so
// a cold hit never blocks or spins. Idle entries are demoted here rather than
// on the read path.
func (s *Service[U]) promoteUser(user U, now int64) {
	current := s.users.Load()
	if current == nil {
		return
	}
	userIdCipher, loaded := current.idCipher[user]
	if !loaded {
		return
	}
	hot := make([]authEntry[U], 0, len(current.hot)+1)
	for i := range current.hot {
		entry := &current.hot[i]
		if entry.user == user {
			return
		}
		lastAccess := atomic.LoadInt64(&entry.lastAccess)
		if now-lastAccess > authHotIdleSeconds {
			continue
		}
		hot = append(hot, authEntry[U]{user: entry.user, cipher: entry.cipher, lastAccess: lastAccess})
	}
	hot = append(hot, authEntry[U]{user: user, cipher: userIdCipher, lastAccess: now})
	s.users.CompareAndSwap(current, &userTable[U]{key: current.key, idCipher: current.idCipher, hot: hot, cold: current.cold})
}

func (s *Service[U]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	const headerLenBufferLen = 2 + CipherOverhead
	const aeadMinHeaderLen = 16 + headerLenBufferLen + 8 + CipherOverhead + 42
	minHeaderLen := aeadMinHeaderLen
	if len(s.alterIds) > 0 {
		minHeaderLen = 16 + 38
	}

	requestBuffer := buf.New()
	defer requestBuffer.Release()

	if !s.disableHeaderProtect {
		n, err := requestBuffer.ReadOnceFrom(conn)
		if err != nil {
			return err
		}
		if n < minHeaderLen {
			return ErrBadHeader
		}
	} else {
		_, err := requestBuffer.ReadAtLeastFrom(conn, minHeaderLen)
		if err != nil {
			return err
		}
	}

	authId := requestBuffer.To(16)
	var decodedId [16]byte
	var user U
	var found bool

	var timestamp int64
	now := s.time().Unix()
	// One snapshot of the credential tables serves the whole handshake.
	users := s.users.Load()
	if users == nil {
		users = &userTable[U]{}
	}

	// Hot path: users that authenticated recently, in one contiguous slice, so
	// a probe is one AES block decrypt plus a CRC per entry with no map lookups.
	for i := range users.hot {
		entry := &users.hot[i]
		entry.cipher.Decrypt(decodedId[:], authId)
		if crc32.ChecksumIEEE(decodedId[:12]) != binary.BigEndian.Uint32(decodedId[12:]) {
			continue
		}
		// A user opening many connections in the same second would otherwise
		// write the same cache line from every core.
		if atomic.LoadInt64(&entry.lastAccess) != now {
			atomic.StoreInt64(&entry.lastAccess, now)
		}
		user = entry.user
		found = true
		break
	}

	// Cold path: every user, then promote the match into hot.
	if !found {
		for i := range users.cold {
			entry := &users.cold[i]
			entry.cipher.Decrypt(decodedId[:], authId)
			if crc32.ChecksumIEEE(decodedId[:12]) != binary.BigEndian.Uint32(decodedId[12:]) {
				continue
			}
			user = entry.user
			found = true
			s.promoteUser(entry.user, now)
			break
		}
	}
	if found {
		timestamp = int64(binary.BigEndian.Uint64(decodedId[:]))
		if math.Abs(math.Abs(float64(timestamp))-float64(now)) > 120 {
			return ErrBadTimestamp
		}
		if !s.replayFilter.Check(decodedId[:]) {
			return ErrReplay
		}
	}

	var legacyProtocol bool
	var legacyTimestamp uint64
	if !found {
		copy(decodedId[:], authId)
		if currUser, loaded := s.alterIdMap[decodedId]; loaded {
			found = true
			legacyProtocol = true
			user = currUser.User
			legacyTimestamp = uint64(currUser.Time)
		}
	}
	if !found {
		return ErrBadRequest
	}

	ctx = auth.ContextWithUser(ctx, user)
	cmdKey := users.key[user]
	var headerReader io.Reader
	var headerBuffer []byte

	var reader io.Reader
	var err error
	if legacyProtocol {
		requestBuffer.Advance(16)
		reader = io.MultiReader(bytes.NewReader(requestBuffer.Bytes()), conn)

		timeHash := md5.New()
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		headerReader = NewStreamReader(reader, cmdKey[:], timeHash.Sum(nil))
		headerBuffer = make([]byte, 38)
		_, err = io.ReadFull(headerReader, headerBuffer)
		if err != nil {
			return E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
	} else {
		if requestBuffer.Len() < aeadMinHeaderLen {
			return ErrBadHeader
		}

		reader = conn

		const nonceIndex = 16 + headerLenBufferLen
		connectionNonce := requestBuffer.Range(nonceIndex, nonceIndex+8)

		lengthKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, authId, connectionNonce)[:16]
		lengthNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, authId, connectionNonce)[:12]
		lengthBuffer, err := newAesGcm(lengthKey).Open(requestBuffer.Index(16), lengthNonce, requestBuffer.Range(16, nonceIndex), authId)
		if err != nil {
			return err
		}

		const headerIndex = nonceIndex + 8
		headerLength := int(binary.BigEndian.Uint16(lengthBuffer))
		needRead := headerLength + headerIndex + CipherOverhead - requestBuffer.Len()
		if needRead > 0 {
			_, err = requestBuffer.ReadFullFrom(conn, needRead)
			if err != nil {
				return err
			}
		}

		headerKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADKey, authId, connectionNonce)[:16]
		headerNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADIV, authId, connectionNonce)[:12]
		headerBuffer, err = newAesGcm(headerKey).Open(requestBuffer.Index(headerIndex), headerNonce, requestBuffer.Range(headerIndex, headerIndex+headerLength+CipherOverhead), authId)
		if err != nil {
			return err
		}
		// replace with < if support mux
		if len(headerBuffer) <= 38 {
			return E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
		requestBuffer.Advance(headerIndex + headerLength + CipherOverhead)
		headerReader = bytes.NewReader(headerBuffer[38:])
	}

	version := headerBuffer[0]
	if version != Version {
		return E.Extend(ErrBadVersion, version)
	}

	requestBodyKey := make([]byte, 16)
	requestBodyNonce := make([]byte, 16)

	copy(requestBodyKey, headerBuffer[17:33])
	copy(requestBodyNonce, headerBuffer[1:17])

	responseHeader := headerBuffer[33]
	option := headerBuffer[34]
	paddingLen := int(headerBuffer[35] >> 4)
	security := headerBuffer[35] & 0x0F
	command := headerBuffer[37]
	switch command {
	case CommandTCP, CommandUDP, CommandMux:
	default:
		return E.New("unknown command: ", command)
	}
	switch security {
	case SecurityTypeLegacy, SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305, SecurityTypeNone:
	default:
		return E.Extend(ErrUnsupportedSecurityType, security)
	}
	if command == CommandUDP && option == 0 {
		return E.New("bad packet connection")
	}
	var destination M.Socksaddr
	if command != CommandMux {
		destination, err = AddressSerializer.ReadAddrPort(headerReader)
		if err != nil {
			return err
		}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, headerReader, int64(paddingLen))
		if err != nil {
			return E.Extend(ErrBadHeader, "bad padding")
		}
	}
	err = rw.SkipN(headerReader, 4)
	if err != nil {
		return err
	}
	if !legacyProtocol && requestBuffer.Len() > 0 {
		reader = bufio.NewCachedReader(reader, requestBuffer.ToOwned())
	}
	reader = CreateReader(reader, nil, requestBodyKey, requestBodyNonce, requestBodyKey, requestBodyNonce, security, option)
	if option&RequestOptionChunkStream != 0 && command == CommandTCP || command == CommandMux {
		reader = newChunkReader(reader)
	}
	rawConn := rawServerConn{
		Conn:           conn,
		legacyProtocol: legacyProtocol,
		requestKey:     requestBodyKey,
		requestNonce:   requestBodyNonce,
		responseHeader: responseHeader,
		security:       security,
		option:         option,
		reader:         bufio.NewExtendedReader(reader),
	}

	switch command {
	case CommandTCP:
		s.handler.NewConnectionEx(ctx, &serverConn{rawConn}, source, destination, onClose)
	case CommandUDP:
		s.handler.NewPacketConnectionEx(ctx, &serverPacketConn{rawConn, destination}, source, destination, onClose)
	case CommandMux:
		return HandleMuxConnection(ctx, &serverConn{rawConn}, source, s.handler)
	default:
		return E.New("unknown command: ", command)
	}
	return nil
}

var _ N.EarlyWriter = (*rawServerConn)(nil)

type rawServerConn struct {
	net.Conn
	legacyProtocol bool
	requestKey     []byte
	requestNonce   []byte
	responseHeader byte
	security       byte
	option         byte
	reader         N.ExtendedReader
	writer         N.ExtendedWriter
	vectorised     chunkFramer // the chunk framing layer of writer, nil for the legacy stream
}

func (c *rawServerConn) writeResponse() error {
	if c.legacyProtocol {
		responseKey := md5.Sum(c.requestKey)
		responseNonce := md5.Sum(c.requestNonce)
		headerWriter := NewStreamWriter(c.Conn, responseKey[:], responseNonce[:])
		_, err := headerWriter.Write([]byte{c.responseHeader, c.option, 0, 0})
		if err != nil {
			return E.Cause(err, "write response")
		}
		c.writer = bufio.NewExtendedWriter(CreateWriter(c.Conn, headerWriter, c.requestKey, c.requestNonce, responseKey[:], responseNonce[:], c.security, c.option))
	} else {
		responseBuffer := buf.NewSize(2 + CipherOverhead + 4 + CipherOverhead)
		defer responseBuffer.Release()

		_responseKey := sha256.Sum256(c.requestKey[:])
		responseKey := _responseKey[:16]
		_responseNonce := sha256.Sum256(c.requestNonce[:])
		responseNonce := _responseNonce[:16]

		headerLenKey := KDF(responseKey, KDFSaltConstAEADRespHeaderLenKey)[:16]
		headerLenNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderLenIV)[:12]
		headerLenCipher := newAesGcm(headerLenKey)
		binary.BigEndian.PutUint16(responseBuffer.Extend(2), 4)
		headerLenCipher.Seal(responseBuffer.Index(0), headerLenNonce, responseBuffer.Bytes(), nil)
		responseBuffer.Extend(CipherOverhead)

		headerKey := KDF(responseKey, KDFSaltConstAEADRespHeaderPayloadKey)[:16]
		headerNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
		headerCipher := newAesGcm(headerKey)
		common.Must(
			responseBuffer.WriteByte(c.responseHeader),
			responseBuffer.WriteByte(c.option),
			responseBuffer.WriteZeroN(2),
		)
		const headerIndex = 2 + CipherOverhead
		headerCipher.Seal(responseBuffer.Index(headerIndex), headerNonce, responseBuffer.From(headerIndex), nil)
		responseBuffer.Extend(CipherOverhead)

		_, err := c.Conn.Write(responseBuffer.Bytes())
		if err != nil {
			return err
		}

		writer := CreateWriter(c.Conn, nil, c.requestKey, c.requestNonce, responseKey, responseNonce, c.security, c.option)
		c.writer = bufio.NewExtendedWriter(writer)
		c.vectorised = vectorisedChunkWriter(writer)
	}
	return nil
}

// chunked reports whether the response is a chunk stream whose framing can be
// applied in place, which is what the vectorised path relies on.
func (c *rawServerConn) chunked() bool {
	if c.legacyProtocol || c.option&RequestOptionChunkStream == 0 {
		return false
	}
	switch c.security {
	case SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305, SecurityTypeNone:
		return true
	}
	return false
}

// chunkFramer is the layer of a CreateWriter chain that frames chunks in
// place and can hand a batch of them down as one writev.
type chunkFramer interface {
	N.VectorisedWriter
	N.VectorisedWriteCreator
}

// writeBuffers writes a batch one buffer at a time, for a writer whose way
// down to the socket cannot take a batch.
func writeBuffers(writer N.ExtendedWriter, buffers []*buf.Buffer) error {
	for index, buffer := range buffers {
		err := writer.WriteBuffer(buffer)
		if err != nil {
			buf.ReleaseMulti(buffers[index+1:])
			return err
		}
	}
	return nil
}

// vectorisedChunkWriter finds the framing layer of a CreateWriter chain;
// nil when the chain has none (legacy stream).
func vectorisedChunkWriter(writer io.Writer) chunkFramer {
	for {
		switch w := writer.(type) {
		case *AEADWriter, *StreamChunkWriter, *AEADChunkWriter:
			return w.(chunkFramer)
		case *bufio.ChunkWriter:
			writer = w.Upstream().(io.Writer)
		case *bufio.ExtendedWriterWrapper:
			writer = w.Writer
		default:
			return nil
		}
	}
}

// splitChunks makes every buffer of a batch fit one chunk with the headroom
// the framing needs. Buffers that already do pass through untouched, which is
// the case for everything the relay reads once it knows WriterMTU. A larger
// buffer keeps its first chunk in place and copies the rest out before the
// first chunk is sealed, because the tag lands on the bytes that follow it.
func splitChunks(buffers []*buf.Buffer) []*buf.Buffer {
	fits := func(buffer *buf.Buffer) bool {
		return buffer.Len() <= WriteChunkSize && buffer.Start() >= MaxFrontHeadroom && buffer.FreeLen() >= MaxRearHeadroom
	}
	needWork := false
	for _, buffer := range buffers {
		if buffer.IsEmpty() || !fits(buffer) {
			needWork = true
			break
		}
	}
	if !needWork {
		return buffers
	}
	chunks := make([]*buf.Buffer, 0, len(buffers)+4)
	for _, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		if fits(buffer) {
			chunks = append(chunks, buffer)
			continue
		}
		data := buffer.Bytes()
		keepHead := buffer.Start() >= MaxFrontHeadroom && buffer.FreeLen() >= MaxRearHeadroom
		if keepHead {
			// Only too long: the head stays where it is.
			buffer.Truncate(WriteChunkSize)
			chunks = append(chunks, buffer)
			data = data[WriteChunkSize:]
		}
		for len(data) > 0 {
			pieceLen := len(data)
			if pieceLen > WriteChunkSize {
				pieceLen = WriteChunkSize
			}
			piece := buf.NewSize(MaxFrontHeadroom + pieceLen + MaxRearHeadroom)
			piece.Resize(MaxFrontHeadroom, 0)
			common.Must1(piece.Write(data[:pieceLen]))
			chunks = append(chunks, piece)
			data = data[pieceLen:]
		}
		if !keepHead {
			buffer.Release()
		}
	}
	return chunks
}

func (c *rawServerConn) Close() error {
	return common.Close(
		c.Conn,
		c.reader,
	)
}

func (c *rawServerConn) FrontHeadroom() int {
	return MaxFrontHeadroom
}

func (c *rawServerConn) RearHeadroom() int {
	return MaxRearHeadroom
}

func (c *rawServerConn) ReaderOverhead() int {
	return ReaderOverhead(c.security, c.option)
}

func (c *rawServerConn) NeedHandshakeForWrite() bool {
	return c.writer == nil
}

func (c *rawServerConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *rawServerConn) Upstream() any {
	return c.Conn
}

type serverConn struct {
	rawServerConn
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

var _ N.ReadWaitCreator = (*serverConn)(nil)

// CreateReadWaiter lets the relay take chunks straight from the chunk stream
// reader, which allocates each one only once its length has arrived, instead
// of parking a pooled buffer on the connection while it waits.
func (c *serverConn) CreateReadWaiter() (N.ReadWaiter, bool) {
	waiter, isWaiter := c.reader.(N.ReadWaiter)
	return waiter, isWaiter
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(b)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			buffer.Release()
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}

var (
	_ N.WriterWithMTU          = (*serverConn)(nil)
	_ N.VectorisedWriteCreator = (*serverConn)(nil)
	_ N.VectorisedWriter       = (*serverConn)(nil)
)

// WriterMTU tells the relay how much fits in one chunk, so it reads from the
// peer in chunk-sized pieces that are framed in place instead of being split
// and copied here.
func (c *serverConn) WriterMTU() int {
	if !c.chunked() {
		return 0
	}
	return WriteChunkSize
}

// CreateVectorisedWriter lets the relay hand over a batch of chunks at a time
// once a connection carries enough data; see WriteVectorised. It says no when
// the framing cannot be applied in place, and also when nothing underneath
// takes a writev, so the relay keeps its single-buffer path rather than
// batching into a copy.
func (c *serverConn) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	if !c.chunked() {
		return nil, false
	}
	if c.writer == nil {
		// No chain to ask before the response has gone out; the answer only
		// depends on the connection the chain gets built on.
		if _, created := bufio.CreateVectorisedWriter(c.Conn); !created {
			return nil, false
		}
		return c, true
	}
	if _, created := c.vectorised.CreateVectorisedWriter(); !created {
		return nil, false
	}
	return c, true
}

// WriteVectorised writes a batch of chunks with one call down the stack: the
// response header first if it has not gone out yet, then every buffer framed
// and sealed in place and sent with a single writev.
func (c *serverConn) WriteVectorised(buffers []*buf.Buffer) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
	}
	if c.vectorised == nil {
		return writeBuffers(c.writer, buffers)
	}
	return c.vectorised.WriteVectorised(splitChunks(buffers))
}

func (c *serverConn) WriteTo(w io.Writer) (n int64, err error) {
	return bufio.Copy(w, c.reader)
}

func (c *serverConn) ReadFrom(r io.Reader) (n int64, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return bufio.Copy(c.writer, r)
}

var _ PacketConn = (*serverPacketConn)(nil)

type serverPacketConn struct {
	rawServerConn
	destination M.Socksaddr
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.reader.Read(p)
	if err != nil {
		return
	}
	addr = c.destination.UDPAddr()
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = c.reader.ReadBuffer(buffer)
	if err != nil {
		return
	}
	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}
