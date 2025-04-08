package hash

import (
	"crypto"
	"fmt"
)

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
