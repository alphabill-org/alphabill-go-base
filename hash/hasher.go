package hash

import (
	"fmt"
	"hash"
	"io"

	"github.com/fxamacker/cbor/v2"
)

type EncoderFactory func(w io.Writer) (*cbor.Encoder, error)

/*
New creates "hash calculator" using given hash function and encoder.
Values written to the hash are encoded by the encoder before hashing.
*/
func New(h hash.Hash, encCtor EncoderFactory) (*Hash, error) {
	enc, err := encCtor(h)
	if err != nil {
		return nil, fmt.Errorf("creating encoder: %w", err)
	}
	return &Hash{h: h, enc: enc, encCtor: encCtor}, nil
}

type Hash struct {
	h       hash.Hash
	enc     *cbor.Encoder
	encCtor EncoderFactory
	err     error
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
Write adds the argument as is (ie raw bytes, without encoding) to the hash.
*/
func (h *Hash) WriteRaw(d []byte) {
	if h.err != nil {
		return
	}
	_, h.err = h.h.Write(d)
}

func (h *Hash) Reset() {
	h.h.Reset()
	h.enc, h.err = h.encCtor(h.h)
}

func (h Hash) Sum() ([]byte, error) {
	return h.h.Sum(nil), h.err
}
