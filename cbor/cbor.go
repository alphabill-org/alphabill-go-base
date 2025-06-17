/*
Package cbor provides CBOR encoding/decoding functions.

It's a thin wrapper for github.com/fxamacker/cbor/v2, the reason for
having it is to make sure we use the same encoding options everywhere.
*/
package cbor

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"

	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

type (
	ABTag = uint64

	RawCBOR []byte

	TaggedCBOR = RawCBOR
)

var (
	encMode cbor.EncMode

	cborNil = []byte{0xf6}
)

/*
Set Core Deterministic Encoding as standard. See <https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c>.
*/
func cborEncoder() (_ cbor.EncMode, err error) {
	if encMode != nil {
		return encMode, nil
	}
	if encMode, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		return nil, err
	}
	return encMode, nil
}

func Marshal(v any) ([]byte, error) {
	enc, err := cborEncoder()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(v)
}

func MarshalTagged(tag ABTag, arr ...any) ([]byte, error) {
	data, err := Marshal(arr)
	if err != nil {
		return nil, err
	}
	return Marshal(cbor.RawTag{
		Number:  tag,
		Content: data,
	})
}

func MarshalTaggedValue(tag ABTag, v any) ([]byte, error) {
	data, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	return Marshal(cbor.RawTag{
		Number:  tag,
		Content: data,
	})
}

func Unmarshal(data []byte, v any) error {
	return cbor.Unmarshal(data, v)
}

func UnmarshalTagged(data []byte) (ABTag, []any, error) {
	var raw cbor.RawTag
	if err := Unmarshal(data, &raw); err != nil {
		return 0, nil, err
	}
	arr := make([]any, 0)
	if err := Unmarshal(raw.Content, &arr); err != nil {
		return 0, nil, err
	}
	return raw.Number, arr, nil
}

func UnmarshalTaggedValue(tag ABTag, data []byte, v any) error {
	var raw cbor.RawTag
	if err := Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Number != tag {
		return fmt.Errorf("unexpected tag: %d, expected: %d", raw.Number, tag)
	}

	if err := Unmarshal(raw.Content, v); err != nil {
		return err
	}
	return nil
}

func GetEncoder(w io.Writer) (*cbor.Encoder, error) {
	enc, err := cborEncoder()
	if err != nil {
		return nil, err
	}
	return enc.NewEncoder(w), nil
}

func Encode(w io.Writer, v any) error {
	enc, err := GetEncoder(w)
	if err != nil {
		return err
	}
	return enc.Encode(v)
}

func GetDecoder(r io.Reader) *cbor.Decoder {
	return cbor.NewDecoder(r)
}

func Decode(r io.Reader, v any) error {
	return GetDecoder(r).Decode(v)
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

func (r RawCBOR) MarshalText() ([]byte, error) {
	return hex.Encode(r), nil
}

func (r *RawCBOR) UnmarshalText(src []byte) error {
	res, err := hex.Decode(src)
	if err == nil {
		*r = res
	}
	return err
}
