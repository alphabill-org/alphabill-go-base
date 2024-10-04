package types

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
)

type testCborType struct {
	_      struct{} `cbor:",toarray"`
	Field1 []byte
	Field2 []byte
}

func TestCborHash(t *testing.T) {
	// define two types that if normally hashed would yield the same hash
	d1 := testCborType{
		Field1: []byte{1, 1},
		Field2: []byte{1, 1},
	}
	d2 := testCborType{
		Field1: []byte{1, 1, 1},
		Field2: []byte{1},
	}
	// verify the normal hashes are equal
	d1NormalHash := hashData(d1)
	d2NormalHash := hashData(d2)
	require.Equal(t, d1NormalHash, d2NormalHash)

	// verify that the cbor hashes are not equal
	d1CborHash, err := HashCBOR(d1, crypto.SHA256)
	require.NoError(t, err)
	d2CborHash, err := HashCBOR(d2, crypto.SHA256)
	require.NoError(t, err)
	require.NotEqual(t, d1CborHash, d2CborHash)
}

func hashData(d testCborType) []byte {
	hasher := crypto.SHA256.New()
	hasher.Write(d.Field1)
	hasher.Write(d.Field2)
	return hasher.Sum(nil)
}
