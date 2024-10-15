package hash

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Hash(t *testing.T) {
	t.Run("value is encoded to cbor", func(t *testing.T) {
		v := cborableData{ID: 292987, Data: []byte{2, 6, 7, 99, 12}, Fail: false}

		h := New(crypto.SHA256.New())
		h.Write(v)
		h1, err := h.Sum()
		require.NoError(t, err)
		require.NotEmpty(t, h1)

		// encode the value manually and hash using
		// WriteRaw - must get the same hash value
		buf, err := encoderMode.Marshal(v)
		require.NoError(t, err)
		h.Reset()
		h.WriteRaw(buf)
		h2, err := h.Sum()
		require.NoError(t, err)
		require.Equal(t, h1, h2)

		// change tha value and hash again - must get different hash value
		v.ID++
		h.Reset()
		h.Write(v)
		h2, err = h.Sum()
		require.NoError(t, err)
		require.NotEqual(t, h1, h2)
	})

	t.Run("encoding error", func(t *testing.T) {
		v := cborableData{Fail: true}

		h := New(crypto.SHA256.New())
		h.Write(1)
		h.Write(v) // should cause error
		h.Write(3)
		_, err := h.Sum()
		require.EqualError(t, err, `nope, can't do`)
	})
}

type cborableData struct {
	_    struct{} `cbor:",toarray"`
	ID   uint64
	Data []byte
	Fail bool
}

func (cd *cborableData) MarshalCBOR() ([]byte, error) {
	if cd.Fail {
		return nil, fmt.Errorf("nope, can't do")
	}

	type alias cborableData
	return encoderMode.Marshal((*alias)(cd))
}
