package hash

import (
	"crypto"
	"crypto/sha256"
	"fmt"
)

var Zero256 = make([]byte, sha256.Size)

// Sum256 returns the SHA256 checksum of the data using the MessageHash augmented hashing.
func Sum256(data []byte) []byte {
	// return zero hash in case data is either empty or missing
	if len(data) == 0 {
		return Zero256
	}
	hsh := sha256.Sum256(data)
	return hsh[:]
}

func NewSha256() *Hash {
	return New(crypto.SHA256.New())
}

func HashValues(hashAlgorithm crypto.Hash, values ...any) ([]byte, error) {
	hasher := New(hashAlgorithm.New())
	for _, value := range values {
		hasher.Write(value)
	}
	res, err := hasher.Sum()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate hash: %w", err)
	}
	return res, nil
}
