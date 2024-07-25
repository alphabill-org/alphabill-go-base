package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

type (
	RawCBOR []byte

	cborHandler struct {
		encMode cbor.EncMode
	}
)

var (
	Cbor = cborHandler{}

	cborNil = []byte{0xf6}
)

type Version uint // or e.g TaggedVersion struct { Version uint; Tag uint }

var NilVersion Version = 0

/*
Set Core Deterministic Encoding as standard. See <https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c>.
*/
func (c *cborHandler) cborEncoder() (cbor.EncMode, error) {
	if c.encMode != nil {
		return c.encMode, nil
	}
	encMode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	c.encMode = encMode
	return encMode, nil
}

func (c cborHandler) Marshal(v any) ([]byte, error) {
	enc, err := c.cborEncoder()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(v)
}

func validateVersion(ver Version) error {
	if ver == NilVersion {
		return errors.New("version is nil")
	}
	return nil
}

func (c cborHandler) MarshalVersioned(ver Version, v any) ([]byte, error) {
	if err := validateVersion(ver); err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	enc, err := c.GetEncoder(buf)
	if err != nil {
		return nil, err
	}
	if err = enc.Encode(ver); err != nil {
		return nil, fmt.Errorf("failed to encode version: %w", err)
	}
	if err = enc.Encode(v); err != nil {
		return nil, fmt.Errorf("failed to encode value: %w", err)
	}
	return buf.Bytes(), nil
}

func (c cborHandler) Unmarshal(data []byte, v any) error {
	return cbor.Unmarshal(data, v)
}

func (c cborHandler) UnmarshalVersioned(data []byte, v any) (Version, error) {
	dec := c.GetDecoder(bytes.NewReader(data))
	var ver Version
	if err := dec.Decode(&ver); err != nil {
		return NilVersion, fmt.Errorf("failed to decode version: %w", err)
	}
	return ver, dec.Decode(v)
}

func (c cborHandler) GetEncoder(w io.Writer) (*cbor.Encoder, error) {
	enc, err := c.cborEncoder()
	if err != nil {
		return nil, err
	}
	return enc.NewEncoder(w), nil
}

func (c cborHandler) Encode(w io.Writer, v any) error {
	enc, err := c.GetEncoder(w)
	if err != nil {
		return err
	}
	return enc.Encode(v)
}

func (c cborHandler) GetDecoder(r io.Reader) *cbor.Decoder {
	return cbor.NewDecoder(r)
}

func (c cborHandler) Decode(r io.Reader, v any) error {
	return c.GetDecoder(r).Decode(v)
}

// MarshalCBOR returns r or CBOR nil if r is empty.
func (r RawCBOR) MarshalCBOR() ([]byte, error) {
	if len(r) == 0 {
		return cborNil, nil
	}
	return r, nil
}

// UnmarshalCBOR copies data into r unless it's CBOR "nil marker" - in that
// case r is set to empty slice.
func (r *RawCBOR) UnmarshalCBOR(data []byte) error {
	if r == nil {
		return errors.New("UnmarshalCBOR on nil pointer")
	}
	if bytes.Equal(data, cborNil) {
		*r = (*r)[0:0]
	} else {
		*r = append((*r)[0:0], data...)
	}
	return nil
}
