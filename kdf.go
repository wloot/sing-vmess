package vmess

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"hash"
	"sync"

	"github.com/sagernet/sing/common"
)

const (
	kdfBlockSize = sha256.BlockSize
	kdfSize      = sha256.Size
	// kdfMaxPath bounds the fast path; VMess uses at most two path elements
	// (auth ID and connection nonce).
	kdfMaxPath = 4
)

// KDF is the VMess AEAD key derivation: HMAC-SHA256 nested once per level,
// keyed from the outside in with the KDF constant, salt and path elements,
// applied to key.
//
// Expanding the nesting gives 2^depth SHA-256 computations whose messages all
// start with the padded constant and the padded salt. Those two blocks only
// depend on the salt, so their SHA-256 state is computed once per salt and each
// leaf resumes from it; the whole tree is then evaluated with one hash object
// and a few scratch buffers from a pool, so a derivation allocates nothing but
// its result. Inputs the fast path does not cover fall back to the plain
// nested-HMAC construction, which remains the reference.
func KDF(key []byte, salt string, path ...[]byte) []byte {
	if len(salt) > kdfBlockSize || len(path) > kdfMaxPath {
		return kdfNested(key, salt, path...)
	}
	for _, element := range path {
		if len(element) > kdfBlockSize {
			return kdfNested(key, salt, path...)
		}
	}
	templates := kdfTemplatesFor(salt)
	var pads [kdfMaxPath][2][kdfBlockSize]byte
	for i, element := range path {
		kdfPad(&pads[i], element)
	}
	workspace := kdfWorkspacePool.Get().(*kdfWorkspace)
	digest := workspace.level(templates, pads[:len(path)], 1+len(path), key)
	kdfWorkspacePool.Put(workspace)
	out := make([]byte, kdfSize)
	copy(out, digest[:])
	return out
}

// kdfPad fills the HMAC inner and outer key blocks for a key of at most one
// block.
func kdfPad(pad *[2][kdfBlockSize]byte, key []byte) {
	copy(pad[0][:], key)
	copy(pad[1][:], key)
	for i := range pad[0] {
		pad[0][i] ^= 0x36
		pad[1][i] ^= 0x5c
	}
}

// kdfTemplates holds the marshaled SHA-256 state after absorbing the padded
// KDF constant followed by the padded salt (inner and outer variants), and
// after the padded constant alone: the three prefixes every leaf starts with.
type kdfTemplates struct {
	innerInner []byte
	innerOuter []byte
	outer      []byte
}

var kdfTemplateCache sync.Map // salt -> *kdfTemplates

func kdfTemplatesFor(salt string) *kdfTemplates {
	if cached, loaded := kdfTemplateCache.Load(salt); loaded {
		return cached.(*kdfTemplates)
	}
	var constantPad, saltPad [2][kdfBlockSize]byte
	kdfPad(&constantPad, []byte(KDFSaltConstVMessAEADKDF))
	kdfPad(&saltPad, []byte(salt))
	digest := sha256.New()
	marshal := func(blocks ...[]byte) []byte {
		digest.Reset()
		for _, block := range blocks {
			common.Must1(digest.Write(block))
		}
		return common.Must1(digest.(encoding.BinaryMarshaler).MarshalBinary())
	}
	templates := &kdfTemplates{
		innerInner: marshal(constantPad[0][:], saltPad[0][:]),
		innerOuter: marshal(constantPad[0][:], saltPad[1][:]),
		outer:      marshal(constantPad[1][:]),
	}
	cached, _ := kdfTemplateCache.LoadOrStore(salt, templates)
	return cached.(*kdfTemplates)
}

type kdfWorkspace struct {
	hash    hash.Hash
	state   encoding.BinaryUnmarshaler
	digest  [kdfSize]byte
	chain   [kdfSize]byte
	scratch [kdfMaxPath][]byte
}

var kdfWorkspacePool = sync.Pool{
	New: func() any {
		digest := sha256.New()
		return &kdfWorkspace{hash: digest, state: digest.(encoding.BinaryUnmarshaler)}
	},
}

// resume hashes message on top of a template state.
func (w *kdfWorkspace) resume(template []byte, message []byte) [kdfSize]byte {
	common.Must(w.state.UnmarshalBinary(template))
	common.Must1(w.hash.Write(message))
	w.hash.Sum(w.digest[:0])
	return w.digest
}

// level evaluates the HMAC at the given nesting level over message. Level 1
// is the salt level, whose four leaves resume from the templates; deeper
// levels wrap the level below with the padded path key, inner then outer.
func (w *kdfWorkspace) level(templates *kdfTemplates, pads [][2][kdfBlockSize]byte, level int, message []byte) [kdfSize]byte {
	if level == 1 {
		w.chain = w.resume(templates.innerInner, message)
		w.chain = w.resume(templates.outer, w.chain[:])
		w.chain = w.resume(templates.innerOuter, w.chain[:])
		return w.resume(templates.outer, w.chain[:])
	}
	pad := &pads[level-2]
	scratch := append(w.scratch[level-2][:0], pad[0][:]...)
	scratch = append(scratch, message...)
	inner := w.level(templates, pads, level-1, scratch)
	scratch = append(scratch[:0], pad[1][:]...)
	scratch = append(scratch, inner[:]...)
	w.scratch[level-2] = scratch
	return w.level(templates, pads, level-1, scratch)
}

// kdfNested is the construction as specified, one hmac.New per level; it is
// the reference for the fast path and handles inputs the fast path declines.
func kdfNested(key []byte, salt string, path ...[]byte) []byte {
	hmacCreator := &hMacCreator{value: []byte(KDFSaltConstVMessAEADKDF)}
	hmacCreator = &hMacCreator{value: []byte(salt), parent: hmacCreator}
	for _, v := range path {
		hmacCreator = &hMacCreator{value: v, parent: hmacCreator}
	}
	hmacf := hmacCreator.Create()
	hmacf.Write(key)
	return hmacf.Sum(nil)
}

type hMacCreator struct {
	parent *hMacCreator
	value  []byte
}

func (h *hMacCreator) Create() hash.Hash {
	if h.parent == nil {
		return hmac.New(sha256.New, h.value)
	}
	return hmac.New(h.parent.Create, h.value)
}
