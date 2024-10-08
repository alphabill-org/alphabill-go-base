package types

import (
	"crypto"
	"fmt"
)

// HashCBOR encodes the provided "data" to CBOR and calculates hash using the provided "hashAlgorithm".
// The "data" parameter should be a CBOR struct with the "toarray" tag.
// The purpose of CBOR encoding before hashing is to avoid "field offset attacks" e.g. when two structs of the same
// type, but with different values, would yield the same hash if otherwise normally concatenated.
func HashCBOR(data any, hashAlgorithm crypto.Hash) ([]byte, error) {
	dataCBOR, err := Cbor.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cbor: %w", err)
	}
	hasher := hashAlgorithm.New()
	hasher.Write(dataCBOR)
	return hasher.Sum(nil), nil
}
