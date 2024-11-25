package types

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/stretchr/testify/require"
)

var ir = &InputRecord{
	Version:         1,
	PreviousHash:    []byte{0, 0, 1},
	Hash:            []byte{0, 0, 2},
	BlockHash:       []byte{0, 0, 3},
	SummaryValue:    []byte{0, 0, 4},
	RoundNumber:     1,
	Epoch:           0,
	SumOfEarnedFees: 20,
}

func TestInputRecord_IsValid(t *testing.T) {
	validIR := InputRecord{
		Version:      1,
		PreviousHash: zeroHash,
		Hash:         zeroHash,
		BlockHash:    zeroHash,
		SummaryValue: zeroHash,
		RoundNumber:  1,
		Timestamp:    NewTimestamp(),
	}
	require.NoError(t, validIR.IsValid())

	t.Run("previous hash is nil", func(t *testing.T) {
		testIR := validIR
		testIR.PreviousHash = nil
		require.ErrorIs(t, ErrPreviousHashIsNil, testIR.IsValid())
	})

	t.Run("hash is nil", func(t *testing.T) {
		testIR := validIR
		testIR.Hash = nil
		require.ErrorIs(t, ErrHashIsNil, testIR.IsValid())
	})

	t.Run("block hash is nil", func(t *testing.T) {
		testIR := validIR
		testIR.BlockHash = nil
		require.ErrorIs(t, ErrBlockHashIsNil, testIR.IsValid())
	})

	t.Run("summary value hash is nil", func(t *testing.T) {
		testIR := validIR
		testIR.SummaryValue = nil
		require.ErrorIs(t, ErrSummaryValueIsNil, testIR.IsValid())
	})

	t.Run("state changes, but block hash is nil", func(t *testing.T) {
		testIR := &InputRecord{
			Version:         1,
			PreviousHash:    zeroHash,
			Hash:            []byte{1, 2, 3},
			BlockHash:       zeroHash,
			SummaryValue:    []byte{2, 3, 4},
			SumOfEarnedFees: 1,
			RoundNumber:     1,
			Timestamp:       NewTimestamp(),
		}
		require.EqualError(t, testIR.IsValid(), "block hash is 0H but state hash changed")
	})

	t.Run("state does not change, but block hash is not 0H", func(t *testing.T) {
		testIR := &InputRecord{
			Version:         1,
			PreviousHash:    zeroHash,
			Hash:            zeroHash,
			BlockHash:       []byte{1, 2, 3},
			SummaryValue:    []byte{2, 3, 4},
			SumOfEarnedFees: 1,
			RoundNumber:     1,
			Timestamp:       NewTimestamp(),
		}
		require.EqualError(t, testIR.IsValid(), "state hash didn't change but block hash is not 0H")
	})

	t.Run("timestamp unassigned", func(t *testing.T) {
		testIR := validIR
		testIR.Timestamp = 0
		require.EqualError(t, testIR.IsValid(), `timestamp is unassigned`)
	})

	t.Run("version unassigned", func(t *testing.T) {
		testIR := validIR
		testIR.Version = 0
		require.EqualError(t, testIR.IsValid(), `invalid version (type *types.InputRecord)`)
	})

	t.Run("unmarshal CBOR - ok", func(t *testing.T) {
		irBytes, err := validIR.MarshalCBOR()
		require.NoError(t, err)
		require.NotNil(t, irBytes)

		ir2 := &InputRecord{}
		require.NoError(t, ir2.UnmarshalCBOR(irBytes))
		require.Equal(t, validIR, *ir2)
	})

	t.Run("unmarshal CBOR - invalid version", func(t *testing.T) {
		validIR.Version = 2
		irBytes, err := validIR.MarshalCBOR()
		require.NoError(t, err)
		require.NotNil(t, irBytes)

		ir2 := &InputRecord{}
		require.ErrorContains(t, ir2.UnmarshalCBOR(irBytes), "invalid version (type *types.InputRecord), expected 1, got 2")
	})
}

func TestInputRecord_IsNil(t *testing.T) {
	var ir *InputRecord
	require.ErrorIs(t, ir.IsValid(), ErrInputRecordIsNil)
}

func TestInputRecord_AddToHasher(t *testing.T) {
	ir = &InputRecord{
		Version:         1,
		PreviousHash:    []byte{0, 0, 1},
		Hash:            []byte{0, 0, 2},
		BlockHash:       []byte{0, 0, 3},
		SummaryValue:    []byte{0, 0, 4},
		RoundNumber:     1,
		Epoch:           0,
		Timestamp:       1731504540,
		SumOfEarnedFees: 20,
	}
	hasher := sha256.New()
	abhasher := abhash.New(hasher)
	ir.AddToHasher(abhasher)
	hash := hasher.Sum(nil)
	require.Equal(t, []byte{0x51, 0xb6, 0x6f, 0x91, 0x65, 0x3a, 0xc0, 0x63, 0x1b, 0xe4, 0x73, 0x6f, 0x4, 0x76, 0xb9, 0xf7, 0x45, 0xbb, 0x80, 0x9b, 0xf4, 0xba, 0xd8, 0x24, 0x2, 0xdc, 0x80, 0x83, 0x2d, 0x31, 0xf4, 0x19}, hash)
}

func Test_EqualIR(t *testing.T) {
	var irA = &InputRecord{
		PreviousHash:    []byte{1, 1, 1},
		Hash:            []byte{2, 2, 2},
		BlockHash:       []byte{3, 3, 3},
		SummaryValue:    []byte{4, 4, 4},
		RoundNumber:     2,
		SumOfEarnedFees: 33,
	}
	t.Run("equal", func(t *testing.T) {
		irB := &InputRecord{
			PreviousHash:    []byte{1, 1, 1},
			Hash:            []byte{2, 2, 2},
			BlockHash:       []byte{3, 3, 3},
			SummaryValue:    []byte{4, 4, 4},
			RoundNumber:     2,
			SumOfEarnedFees: 33,
		}
		require.True(t, EqualIR(irA, irB))
	})
	t.Run("Previous hash not equal", func(t *testing.T) {
		irB := &InputRecord{
			PreviousHash:    []byte{1, 1},
			Hash:            []byte{2, 2, 2},
			BlockHash:       []byte{3, 3, 3},
			SummaryValue:    []byte{4, 4, 4},
			RoundNumber:     2,
			SumOfEarnedFees: 33,
		}
		require.False(t, EqualIR(irA, irB))
	})
	t.Run("Hash not equal", func(t *testing.T) {
		irB := &InputRecord{
			PreviousHash:    []byte{1, 1, 1},
			Hash:            []byte{2, 2, 2, 3},
			BlockHash:       []byte{3, 3, 3},
			SummaryValue:    []byte{4, 4, 4},
			RoundNumber:     2,
			SumOfEarnedFees: 33,
		}
		require.False(t, EqualIR(irA, irB))
	})
	t.Run("Block hash not equal", func(t *testing.T) {
		irB := &InputRecord{
			PreviousHash:    []byte{1, 1, 1},
			Hash:            []byte{2, 2, 2},
			BlockHash:       nil,
			SummaryValue:    []byte{4, 4, 4},
			RoundNumber:     2,
			SumOfEarnedFees: 33,
		}
		require.False(t, EqualIR(irA, irB))
	})
	t.Run("Summary value not equal", func(t *testing.T) {
		irB := &InputRecord{
			PreviousHash:    []byte{1, 1, 1},
			Hash:            []byte{2, 2, 2},
			BlockHash:       []byte{3, 3, 3},
			SummaryValue:    []byte{},
			RoundNumber:     2,
			SumOfEarnedFees: 33,
		}
		require.False(t, EqualIR(irA, irB))
	})
	t.Run("RoundNumber not equal", func(t *testing.T) {
		irB := &InputRecord{
			PreviousHash:    []byte{1, 1, 1},
			Hash:            []byte{2, 2, 2},
			BlockHash:       []byte{3, 3, 3},
			SummaryValue:    []byte{4, 4, 4},
			RoundNumber:     1,
			SumOfEarnedFees: 33,
		}
		require.False(t, EqualIR(irA, irB))
	})
	t.Run("SumOfEarnedFees not equal", func(t *testing.T) {
		irB := &InputRecord{
			PreviousHash:    []byte{1, 1, 1},
			Hash:            []byte{2, 2, 2},
			BlockHash:       []byte{3, 3, 3},
			SummaryValue:    []byte{4, 4, 4},
			RoundNumber:     2,
			SumOfEarnedFees: 1,
		}
		require.False(t, EqualIR(irA, irB))
	})
}

func Test_AssertEqualIR(t *testing.T) {
	var irA = InputRecord{
		PreviousHash:    []byte{1, 1, 1},
		Hash:            []byte{2, 2, 2},
		BlockHash:       []byte{3, 3, 3},
		SummaryValue:    []byte{4, 4, 4},
		Timestamp:       20241113,
		Epoch:           1,
		RoundNumber:     2,
		SumOfEarnedFees: 33,
	}

	t.Run("equal", func(t *testing.T) {
		irB := irA
		require.NoError(t, AssertEqualIR(&irA, &irB))
	})

	t.Run("Previous hash not equal", func(t *testing.T) {
		irB := irA
		irB.PreviousHash = []byte{1, 1}
		require.EqualError(t, AssertEqualIR(&irA, &irB), "previous state hash is different: 010101 vs 0101")
	})

	t.Run("Hash not equal", func(t *testing.T) {
		irB := irA
		irB.Hash = []byte{2, 2, 2, 3}
		require.EqualError(t, AssertEqualIR(&irA, &irB), "state hash is different: 020202 vs 02020203")
	})

	t.Run("Block hash not equal", func(t *testing.T) {
		irB := irA
		irB.BlockHash = nil
		require.EqualError(t, AssertEqualIR(&irA, &irB), "block hash is different: 030303 vs ")
	})

	t.Run("Summary value not equal", func(t *testing.T) {
		irB := irA
		irB.SummaryValue = []byte{}
		require.EqualError(t, AssertEqualIR(&irA, &irB), "summary value is different: [4 4 4] vs []")
	})

	t.Run("RoundNumber not equal", func(t *testing.T) {
		irB := irA
		irB.RoundNumber = 1
		require.EqualError(t, AssertEqualIR(&irA, &irB), "round number is different: 2 vs 1")
	})

	t.Run("SumOfEarnedFees not equal", func(t *testing.T) {
		irB := irA
		irB.SumOfEarnedFees = 1
		require.EqualError(t, AssertEqualIR(&irA, &irB), "sum of fees is different: 33 vs 1")
	})

	t.Run("Timestamp not equal", func(t *testing.T) {
		irB := irA
		irB.Timestamp = 0
		require.EqualError(t, AssertEqualIR(&irA, &irB), "timestamp is different: 20241113 vs 0")
	})

	t.Run("Epoch not equal", func(t *testing.T) {
		irB := irA
		irB.Epoch = 10
		require.EqualError(t, AssertEqualIR(&irA, &irB), "epoch is different: 1 vs 10")
	})
}

func TestInputRecord_NewRepeatUC(t *testing.T) {
	repeatUC := ir.NewRepeatIR()
	require.NotNil(t, repeatUC)
	require.True(t, bytes.Equal(ir.Bytes(), repeatUC.Bytes()))
	require.True(t, reflect.DeepEqual(ir, repeatUC))
	ir.RoundNumber++
	require.False(t, bytes.Equal(ir.Bytes(), repeatUC.Bytes()))
}

func TestStringer(t *testing.T) {
	var testIR *InputRecord = nil
	require.Equal(t, "input record is nil", testIR.String())
	testIR = &InputRecord{
		PreviousHash:    []byte{1, 1, 1},
		Hash:            []byte{2, 2, 2},
		BlockHash:       []byte{3, 3, 3},
		SummaryValue:    []byte{4, 4, 4},
		RoundNumber:     2,
		SumOfEarnedFees: 33,
	}
	require.Equal(t, "H: 020202 H': 010101 Bh: 030303 round: 2 epoch: 0 fees: 33 summary: 040404", testIR.String())
}
