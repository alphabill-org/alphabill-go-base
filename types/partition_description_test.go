package types

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_PartitionDescriptionRecord_Hash(t *testing.T) {
	pdr := PartitionDescriptionRecord{
		Version:     1,
		PartitionID: 1,
		TypeIDLen:   8,
		UnitIDLen:   256,
		T2Timeout:   2500 * time.Millisecond,
	}
	pdrHash := doHash(t, &pdr)

	// each call must return the same value
	require.EqualValues(t, pdrHash, doHash(t, &pdr))
	// different hash algorithm should return different value
	h2, err := pdr.Hash(crypto.SHA512)
	require.NoError(t, err)
	require.NotEqualValues(t, pdrHash, h2)

	// make a copy of the struct - must get the same value as original
	pdr2 := pdr // note that "pdr" is not a pointer!
	require.EqualValues(t, pdrHash, doHash(t, &pdr2))

	// change field value in the copy - hash must change
	pdr2.T2Timeout++
	require.NotEqualValues(t, pdrHash, doHash(t, &pdr2))
}

func Test_PartitionDescriptionRecord_IsValid(t *testing.T) {
	validPDR := func() *PartitionDescriptionRecord {
		return &PartitionDescriptionRecord{
			Version:     1,
			NetworkID:   5,
			PartitionID: 1,
			TypeIDLen:   8,
			UnitIDLen:   256,
			T2Timeout:   2500 * time.Millisecond,
		}
	}

	require.NoError(t, validPDR().IsValid())

	t.Run("system description is nil", func(t *testing.T) {
		var s *PartitionDescriptionRecord = nil
		require.EqualError(t, s.IsValid(), "system description record is nil")
	})

	t.Run("network identifier", func(t *testing.T) {
		pdr := validPDR()
		require.EqualValues(t, 5, pdr.GetNetworkID())

		pdr.NetworkID = 0
		require.EqualError(t, pdr.IsValid(), "invalid network identifier: 0")
	})

	t.Run("partition identifier", func(t *testing.T) {
		pdr := validPDR()
		pdr.PartitionID = 0
		require.EqualError(t, pdr.IsValid(), "invalid partition identifier: 00000000")

		pdr.PartitionID = 3
		require.EqualValues(t, 3, pdr.GetPartitionID())
	})

	t.Run("type id length", func(t *testing.T) {
		pdr := validPDR()
		pdr.TypeIDLen = 33
		require.EqualError(t, pdr.IsValid(), "type id length can be up to 32 bits, got 33")

		pdr.TypeIDLen = 7
		require.EqualError(t, pdr.IsValid(), "type id length must be in full bytes, got 0 bytes and 7 bits")

		pdr.TypeIDLen = 9
		require.EqualError(t, pdr.IsValid(), "type id length must be in full bytes, got 1 bytes and 1 bits")
	})

	t.Run("unit id length", func(t *testing.T) {
		pdr := validPDR()
		pdr.UnitIDLen = 63
		require.EqualError(t, pdr.IsValid(), "unit id length must be 64..512 bits, got 63")

		pdr.UnitIDLen = 513
		require.EqualError(t, pdr.IsValid(), "unit id length must be 64..512 bits, got 513")

		pdr.UnitIDLen = 65
		require.EqualError(t, pdr.IsValid(), "unit id length must be in full bytes, got 8 bytes and 1 bits")
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
		pdr := &PartitionDescriptionRecord{
			Version:     1,
			PartitionID: 1,
			TypeIDLen:   8,
			UnitIDLen:   256,
			T2Timeout:   2500 * time.Millisecond,
			Shards:      nil,
		}

		// empty sharding scheme - only empty id is valid
		err := pdr.IsValidShard(ShardID{bits: []byte{0}, length: 1})
		require.EqualError(t, err, `only empty shard ID is valid in a single-shard sharding scheme`)

		require.NoError(t, pdr.IsValidShard(ShardID{}))
	})

	t.Run("non empty scheme", func(t *testing.T) {
		pdr := &PartitionDescriptionRecord{
			Version:     1,
			PartitionID: 1,
			TypeIDLen:   8,
			UnitIDLen:   256,
			T2Timeout:   2500 * time.Millisecond,
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
		pdr := &PartitionDescriptionRecord{
			Version:     1,
			PartitionID: 1,
			TypeIDLen:   8,
			UnitIDLen:   8,
			T2Timeout:   2500 * time.Millisecond,
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
		pdr := &PartitionDescriptionRecord{
			Version:     1,
			PartitionID: 1,
			TypeIDLen:   8,
			UnitIDLen:   8,
			T2Timeout:   2500 * time.Millisecond,
		}
		vf := pdr.UnitIDValidator(ShardID{})

		require.EqualError(t, vf(nil), `expected 2 byte unit ID, got 0 bytes`)

		require.EqualError(t, vf([]byte{1}), `expected 2 byte unit ID, got 1 bytes`)

		require.EqualError(t, vf([]byte{1, 2, 3}), `expected 2 byte unit ID, got 3 bytes`)

		require.NoError(t, vf([]byte{1, 2}))
	})

	t.Run("matching shard ID", func(t *testing.T) {
		pdr := &PartitionDescriptionRecord{
			Version:     1,
			PartitionID: 1,
			TypeIDLen:   8,
			UnitIDLen:   8,
			T2Timeout:   2500 * time.Millisecond,
			Shards: ShardingScheme{
				ShardID{bits: []byte{0}, length: 1},
				ShardID{bits: []byte{1}, length: 1},
			},
		}
		// validator for shard "1"
		vf := pdr.UnitIDValidator(ShardID{bits: []byte{128}, length: 1})

		// unit ID in the shard "0"
		require.EqualError(t, vf([]byte{0b0111_0000, 1}), `unit doesn't belong into the shard`)

		// unit ID in the shard "1"
		require.NoError(t, vf([]byte{0b1000_0000, 2}))
	})
}

func Test_PartitionDescriptionRecord_ComposeUnitID(t *testing.T) {
	pdr := PartitionDescriptionRecord{
		Version:     1,
		PartitionID: 1,
		NetworkID:   5,
		TypeIDLen:   8,
		UnitIDLen:   256,
		T2Timeout:   2500 * time.Millisecond,
	}
	require.NoError(t, pdr.IsValid())

	t.Run("type id out of range", func(t *testing.T) {
		uid, err := pdr.ComposeUnitID(ShardID{}, 1<<pdr.TypeIDLen, func(buf []byte) error { return nil })
		require.EqualError(t, err, `provided unit type ID 0x100 uses more than max allowed 8 bits`)
		require.Empty(t, uid)
	})

	t.Run("prndSh returns error", func(t *testing.T) {
		expErr := fmt.Errorf("no random")
		prndSh := func(buf []byte) error { return expErr }
		uid, err := pdr.ComposeUnitID(ShardID{}, 1, prndSh)
		require.ErrorIs(t, err, expErr)
		require.Empty(t, uid)
	})

	t.Run("success", func(t *testing.T) {
		prndSh := func(buf []byte) error {
			copy(buf, bytes.Repeat([]byte{0xFF}, len(buf)))
			return nil
		}
		uid, err := pdr.ComposeUnitID(ShardID{}, 1<<pdr.TypeIDLen-1, prndSh)
		require.NoError(t, err)
		require.Len(t, uid, int(pdr.UnitIDLen+pdr.TypeIDLen)/8)
	})
}

func Test_PartitionDescriptionRecord_ExtractUnitType(t *testing.T) {
	pdr := PartitionDescriptionRecord{
		Version:     1,
		PartitionID: 1,
		NetworkID:   5,
		TypeIDLen:   8,
		UnitIDLen:   256,
		T2Timeout:   2500 * time.Millisecond,
	}
	require.NoError(t, pdr.IsValid())
	unitID := bytes.Repeat([]byte{0xFF}, int((pdr.UnitIDLen+pdr.TypeIDLen)/8))

	t.Run("type id length out of range", func(t *testing.T) {
		invalidPDR := pdr
		invalidPDR.TypeIDLen = 33
		tid, err := invalidPDR.ExtractUnitType(unitID)
		require.EqualError(t, err, `partition uses 33 bit type identifiers`)
		require.Zero(t, tid)
	})

	t.Run("invalid unit id", func(t *testing.T) {
		tid, err := pdr.ExtractUnitType(unitID[1:])
		require.EqualError(t, err, `expected unit ID length 33 bytes, got 32 bytes`)
		require.Zero(t, tid)

		tid, err = pdr.ExtractUnitType(slices.Concat(unitID, []byte{1}))
		require.EqualError(t, err, `expected unit ID length 33 bytes, got 34 bytes`)
		require.Zero(t, tid)
	})

	t.Run("success", func(t *testing.T) {
		tid, err := pdr.ExtractUnitType(unitID)
		require.NoError(t, err)
		require.EqualValues(t, 0xFF, tid)
	})
}

func Test_PartitionDescriptionRecord_TypeIDRoundtrip(t *testing.T) {
	// test both ComposeUnitID and ExtractUnitType by composing and
	// decomposing extended unit ID

	pdrTemplate := PartitionDescriptionRecord{
		Version:     1,
		PartitionID: 1,
		NetworkID:   5,
		TypeIDLen:   8,
		UnitIDLen:   64,
		T2Timeout:   2500 * time.Millisecond,
	}

	prndSh := func(buf []byte) error {
		copy(buf, bytes.Repeat([]byte{0xFF}, len(buf)))
		return nil
	}

	shards := []ShardID{
		{},
		{bits: []byte{0}, length: 1},
		{bits: []byte{128}, length: 1},
		{bits: []byte{0}, length: 8},
		{bits: []byte{0, 0}, length: 9},
		{bits: []byte{0xFF, 0}, length: 9},
	}

	t.Run("one byte types", func(t *testing.T) {
		pdr := pdrTemplate
		pdr.TypeIDLen = 8
		require.NoError(t, pdr.IsValid())
		uidLastByte := int(pdr.UnitIDLen/8) - 1

		for _, shardID := range shards {
			for _, typeID := range []uint32{0, 1, 2, 7, 8, 128, 255} {
				uid, err := pdr.ComposeUnitID(shardID, typeID, prndSh)
				require.NoError(t, err)
				require.EqualValues(t, 0xFF, uid[uidLastByte], "last byte of the unit id got overwritten?")
				tid, err := pdr.ExtractUnitType(uid)
				require.NoError(t, err)
				if typeID != tid {
					t.Errorf("unit ID %s, expected typeID %d, got %d", uid, typeID, tid)
				}
			}
		}
	})

	t.Run("two byte types", func(t *testing.T) {
		pdr := pdrTemplate
		pdr.TypeIDLen = 16
		require.NoError(t, pdr.IsValid())
		uidLastByte := int(pdr.UnitIDLen/8) - 1

		var typeIDs = []uint32{0, 1, 7, 8, 128, 255, 0x0100, 0x0180, 0x80FF, 0xFF00, 0xFFFF}
		for _, shardID := range shards {
			for _, typeID := range typeIDs {
				uid, err := pdr.ComposeUnitID(shardID, typeID, prndSh)
				require.NoError(t, err)
				require.EqualValues(t, 0xFF, uid[uidLastByte], "last byte of the unit id got overwritten?")
				tid, err := pdr.ExtractUnitType(uid)
				require.NoError(t, err)
				if typeID != tid {
					t.Errorf("unit ID %s, expected typeID %d, got %d", uid, typeID, tid)
				}
			}
		}
	})

	t.Run("three byte types", func(t *testing.T) {
		pdr := pdrTemplate
		pdr.TypeIDLen = 24
		require.NoError(t, pdr.IsValid())
		uidLastByte := int(pdr.UnitIDLen/8) - 1

		var typeIDs = []uint32{0, 1, 128, 255, 0x0100, 0x0180, 0x80FF, 0xFF00, 0xFFFF, 0xFFFF00, 0xFF00FF, 0xFFFFFF}
		for _, shardID := range shards {
			for _, typeID := range typeIDs {
				uid, err := pdr.ComposeUnitID(shardID, typeID, prndSh)
				require.NoError(t, err)
				require.EqualValues(t, 0xFF, uid[uidLastByte], "last byte of the unit id got overwritten?")
				tid, err := pdr.ExtractUnitType(uid)
				require.NoError(t, err)
				if typeID != tid {
					t.Errorf("unit ID %s, expected typeID %d, got %d", uid, typeID, tid)
				}
			}
		}
	})

	t.Run("four byte types", func(t *testing.T) {
		pdr := pdrTemplate
		pdr.TypeIDLen = 32
		require.NoError(t, pdr.IsValid())
		uidLastByte := int(pdr.UnitIDLen/8) - 1

		var typeIDs = []uint32{0, 1, 255, 0x0100, 0xFF00, 0xFFFF, 0xFFFF00, 0xFF00FF, 0xFFFFFF, 0x10000000, 0xFF0FF0FF, 0xFFFFFFFF}
		for _, shardID := range shards {
			for _, typeID := range typeIDs {
				uid, err := pdr.ComposeUnitID(shardID, typeID, prndSh)
				require.NoError(t, err)
				require.EqualValues(t, 0xFF, uid[uidLastByte], "last byte of the unit id got overwritten?")
				tid, err := pdr.ExtractUnitType(uid)
				require.NoError(t, err)
				if typeID != tid {
					t.Errorf("unit ID %s, expected typeID %d, got %d", uid, typeID, tid)
				}
			}
		}
	})
}

func Test_PartitionDescriptionRecord_CBOR(t *testing.T) {
	pdr := &PartitionDescriptionRecord{
		Version:     1,
		PartitionID: 1,
		NetworkID:   5,
		TypeIDLen:   8,
		UnitIDLen:   256,
		T2Timeout:   2500 * time.Millisecond,
	}

	t.Run("Marshal - ok", func(t *testing.T) {
		encoded, err := pdr.MarshalCBOR()
		require.NoError(t, err)

		decoded := &PartitionDescriptionRecord{}
		require.NoError(t, decoded.UnmarshalCBOR(encoded))

		require.EqualValues(t, pdr, decoded)
	})

	t.Run("Unmarshal - invalid version", func(t *testing.T) {
		pdr.Version = 2
		encoded, err := pdr.MarshalCBOR()
		require.NoError(t, err)

		decoded := &PartitionDescriptionRecord{}
		err = decoded.UnmarshalCBOR(encoded)
		require.ErrorContains(t, err, "invalid version (type *types.PartitionDescriptionRecord), expected 1, got 2")
	})
}
