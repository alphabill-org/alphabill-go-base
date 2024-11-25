package hash

import (
	"crypto"
	"crypto/sha256"
	"fmt"
)

var Zero256 = make([]byte, 32)

// Sum256 returns the SHA256 checksum of the data using the MessageHash augmented hashing.
func Sum256(data []byte) []byte {
	// return zero hash in case data is either empty or missing
	if len(data) == 0 {
		return Zero256
	}
	hsh := sha256.Sum256(data)
	return hsh[:]
}

// SumHashes hashes the hashes, for hashing other data units, use hash.New() instead.
func SumHashes(hashAlgorithm crypto.Hash, hashes ...[]byte) []byte {
	hasher := hashAlgorithm.New()
	for _, hash := range hashes {
		hasher.Write(hash)
	}
	return hasher.Sum(nil)
}

func Sum(hashAlgorithm crypto.Hash, values ...any) []byte {
	hasher := New(hashAlgorithm.New())
	for _, value := range values {
		hasher.Write(value)
	}
	res, err := hasher.Sum()
	if err != nil {
		// TODO: propagate error?
		panic(fmt.Errorf("failed to calculate hash: %w", err))
	}
	return res
}
