package orchestration

import (
	"crypto"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
)

/*
PrndSh returns function which generates pseudo-random byte sequence based on the input.
Meant to be used as unit identifier generator in PDR.ComposeUnitID.
Subsequent calls return the same value.
*/
func PrndSh(partition types.PartitionID, shard types.ShardID) func(buf []byte) error {
	return func(buf []byte) error {
		h, err := hash.HashValues(crypto.SHA256, partition, shard)
		if err != nil {
			return fmt.Errorf("hashing seed data: %w", err)
		}
		if n := copy(buf, h); n != len(buf) {
			return fmt.Errorf("requested %d bytes but got %d", len(buf), n)
		}
		return nil
	}
}
