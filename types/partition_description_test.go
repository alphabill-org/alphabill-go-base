package types

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_PartitionDescriptionRecord_Hash(t *testing.T) {
	pdr := PartitionDescriptionRecord{Version: 1,
		SystemIdentifier: 1,
		TypeIdLen:        8,
		UnitIdLen:        256,
		T2Timeout:        2500 * time.Millisecond,
	}
	sdrHash := pdr.Hash(crypto.SHA256)

	// each call must return the same value
	require.EqualValues(t, sdrHash, pdr.Hash(crypto.SHA256))
	// different hash algorithm should return different value
	require.NotEqualValues(t, sdrHash, pdr.Hash(crypto.SHA512))

	// make a copy of the struct - must get the same value as original
	pdr2 := pdr // note that "pdr" is not a pointer!
	require.EqualValues(t, sdrHash, pdr2.Hash(crypto.SHA256))

	// change field value in the copy - hash must change
	pdr2.T2Timeout++
	require.NotEqualValues(t, sdrHash, pdr2.Hash(crypto.SHA256))
}

func Test_PartitionDescriptionRecord_IsValid(t *testing.T) {
	validPDR := func() *PartitionDescriptionRecord {
		return &PartitionDescriptionRecord{Version: 1,
			NetworkIdentifier: 5,
			SystemIdentifier:  1,
			TypeIdLen:         8,
			UnitIdLen:         256,
			T2Timeout:         2500 * time.Millisecond,
		}
	}

	require.NoError(t, validPDR().IsValid())

	t.Run("system description is nil", func(t *testing.T) {
		var s *PartitionDescriptionRecord = nil
		require.EqualError(t, s.IsValid(), "system description record is nil")
	})

	t.Run("network identifier", func(t *testing.T) {
		pdr := validPDR()
		require.EqualValues(t, 5, pdr.GetNetworkIdentifier())

		pdr.NetworkIdentifier = 0
		require.EqualError(t, pdr.IsValid(), "invalid network identifier: 0")
	})

	t.Run("system identifier", func(t *testing.T) {
		pdr := validPDR()
		pdr.SystemIdentifier = 0
		require.EqualError(t, pdr.IsValid(), "invalid system identifier: 00000000")

		pdr.SystemIdentifier = 3
		require.EqualValues(t, 3, pdr.GetSystemIdentifier())
	})

	t.Run("type id length", func(t *testing.T) {
		pdr := validPDR()
		pdr.TypeIdLen = 33
		require.EqualError(t, pdr.IsValid(), "type id length can be up to 32 bits, got 33")
	})

	t.Run("unit id length", func(t *testing.T) {
		pdr := validPDR()
		pdr.UnitIdLen = 63
		require.EqualError(t, pdr.IsValid(), "unit id length must be 64..512 bits, got 63")

		pdr.UnitIdLen = 513
		require.EqualError(t, pdr.IsValid(), "unit id length must be 64..512 bits, got 513")
	})

	t.Run("T2 timeout", func(t *testing.T) {
		pdr := validPDR()
		pdr.T2Timeout = 0
		require.EqualError(t, pdr.IsValid(), "t2 timeout value out of allowed range: 0s")

		pdr.T2Timeout = 499 * time.Millisecond
		require.EqualError(t, pdr.IsValid(), "t2 timeout value out of allowed range: 499ms")

		pdr.T2Timeout = 2 * time.Minute
		require.EqualError(t, pdr.IsValid(), "t2 timeout value out of allowed range: 2m0s")
	})
}

func Test_PartitionDescriptionRecord_IsValidShard(t *testing.T) {
	t.Run("empty scheme", func(t *testing.T) {
		pdr := &PartitionDescriptionRecord{Version: 1,
			SystemIdentifier: 1,
			TypeIdLen:        8,
			UnitIdLen:        256,
			T2Timeout:        2500 * time.Millisecond,
			Shards:           nil,
		}

		// empty sharding scheme - only empty id is valid
		err := pdr.IsValidShard(ShardID{bits: []byte{0}, length: 1})
		require.EqualError(t, err, `only empty shard ID is valid in a single-shard sharding scheme`)

		require.NoError(t, pdr.IsValidShard(ShardID{}))
	})

	t.Run("non empty scheme", func(t *testing.T) {
		pdr := &PartitionDescriptionRecord{Version: 1,
			SystemIdentifier: 1,
			TypeIdLen:        8,
			UnitIdLen:        256,
			T2Timeout:        2500 * time.Millisecond,
			Shards: ShardingScheme{
				ShardID{bits: []byte{0}, length: 1},
				ShardID{bits: []byte{1}, length: 1},
			},
		}

		// empty id is invalid in multi-shard scheme
		err := pdr.IsValidShard(ShardID{})
		require.EqualError(t, err, `empty shard ID is not valid in multi-shard sharding scheme`)

		// single bit IDs "0" and "1" must be valid
		require.NoError(t, pdr.IsValidShard(ShardID{bits: []byte{0}, length: 1}))
		require.NoError(t, pdr.IsValidShard(ShardID{bits: []byte{1}, length: 1}))

		// id which is not in the scheme (two bits)
		err = pdr.IsValidShard(ShardID{bits: []byte{0}, length: 2})
		require.EqualError(t, err, `shard ID 00 doesn't belong into the sharding scheme`)
	})

	t.Run("shard id longer than unit id", func(t *testing.T) {
		pdr := &PartitionDescriptionRecord{Version: 1,
			SystemIdentifier: 1,
			TypeIdLen:        8,
			UnitIdLen:        8,
			T2Timeout:        2500 * time.Millisecond,
			Shards: ShardingScheme{
				ShardID{bits: []byte{0}, length: 1},
				ShardID{bits: []byte{1}, length: 1},
			},
		}
		err := pdr.IsValidShard(ShardID{bits: []byte{0, 1}, length: 9})
		require.EqualError(t, err, `partition has 8 bit unit IDs but shard ID is 9 bits`)
	})
}

func Test_PartitionDescriptionRecord_UnitIdValidator(t *testing.T) {
	t.Run("unit ID length", func(t *testing.T) {
		pdr := &PartitionDescriptionRecord{Version: 1,
			SystemIdentifier: 1,
			TypeIdLen:        8,
			UnitIdLen:        8,
			T2Timeout:        2500 * time.Millisecond,
		}
		vf := pdr.UnitIdValidator(ShardID{})

		require.EqualError(t, vf(nil), `expected 2 byte unit ID, got 0 bytes`)

		require.EqualError(t, vf([]byte{1}), `expected 2 byte unit ID, got 1 bytes`)

		require.EqualError(t, vf([]byte{1, 2, 3}), `expected 2 byte unit ID, got 3 bytes`)

		require.NoError(t, vf([]byte{1, 2}))
	})

	t.Run("matching shard ID", func(t *testing.T) {
		pdr := &PartitionDescriptionRecord{Version: 1,
			SystemIdentifier: 1,
			TypeIdLen:        8,
			UnitIdLen:        8,
			T2Timeout:        2500 * time.Millisecond,
			Shards: ShardingScheme{
				ShardID{bits: []byte{0}, length: 1},
				ShardID{bits: []byte{1}, length: 1},
			},
		}
		// validator for shard "1"
		vf := pdr.UnitIdValidator(ShardID{bits: []byte{128}, length: 1})

		// unit ID in the shard "0"
		require.EqualError(t, vf([]byte{0b0111_0000, 1}), `unit doesn't belong into the shard`)

		// unit ID in the shard "1"
		require.NoError(t, vf([]byte{0b1000_0000, 2}))
	})
}
