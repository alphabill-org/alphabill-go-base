package hash

import (
	"fmt"
	"hash"

	"github.com/fxamacker/cbor/v2"
)

type Hasher interface {
	Write(any)
	WriteRaw([]byte)
	Reset()
	Sum() ([]byte, error)
	Size() int
}

/*
New creates "hash calculator" using given hash function.
Values written to the hash are encoded as CBOR before hashing.
*/
func New(h hash.Hash) *Hash {
	return &Hash{h: h, enc: encoderMode.NewEncoder(h)}
}

type Hash struct {
	h   hash.Hash
	enc *cbor.Encoder
	err error
}

/*
Write serializes argument as CBOR and adds it to the hash.
*/
func (h *Hash) Write(v any) {
	if h.err != nil {
		return
	}
	h.err = h.enc.Encode(v)
}

/*
Write adds the argument as is (ie raw bytes, without additional encoding) to the hash.
*/
func (h *Hash) WriteRaw(d []byte) {
	if h.err != nil {
		return
	}
	_, h.err = h.h.Write(d)
}

func (h *Hash) Reset() {
	h.h.Reset()
	h.err = nil
	h.enc = encoderMode.NewEncoder(h.h)
}

func (h *Hash) Size() int {
	return h.h.Size()
}

/*
Sum returns the hash value calculated and first error (if any) that happened
during the hashing (in case of non-nil error the hash value is not valid).
*/
func (h Hash) Sum() ([]byte, error) {
	return h.h.Sum(nil), h.err
}

var encoderMode cbor.EncMode

func init() {
	// it is extremely unlikely that building encoder mode from options
	// provided by the CBOR library fails (ie memory corruption...)
	var err error
	if encoderMode, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		panic(fmt.Errorf("initializing CBOR encoder mode: %w", err))
	}
}
