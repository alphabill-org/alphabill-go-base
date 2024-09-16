package types

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_SystemDescriptionRecord_Hash(t *testing.T) {
	pdr := PartitionDescriptionRecord{
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

func TestSystemDescriptionRecord_IsValid(t *testing.T) {
	validPDR := func() *PartitionDescriptionRecord {
		return &PartitionDescriptionRecord{
			SystemIdentifier: 1,
			TypeIdLen:        8,
			UnitIdLen:        256,
			T2Timeout:        2500 * time.Millisecond,
		}
	}

	require.NoError(t, validPDR().IsValid())

	t.Run("system description is nil", func(t *testing.T) {
		var s *PartitionDescriptionRecord = nil
		require.EqualError(t, s.IsValid(), "system description record is nil")
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
