package types

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"

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
	t.Run("previous hash is nil", func(t *testing.T) {
		testIR := &InputRecord{
			Version:      1,
			PreviousHash: nil,
			Hash:         zeroHash,
			BlockHash:    zeroHash,
			SummaryValue: zeroHash,
		}
		require.ErrorIs(t, ErrPreviousHashIsNil, testIR.IsValid())
	})
	t.Run("hash is nil", func(t *testing.T) {
		testIR := &InputRecord{
			Version:      1,
			PreviousHash: zeroHash,
			Hash:         nil,
			BlockHash:    zeroHash,
			SummaryValue: zeroHash,
		}
		require.ErrorIs(t, ErrHashIsNil, testIR.IsValid())
	})
	t.Run("block hash is nil", func(t *testing.T) {
		testIR := &InputRecord{
			Version:      1,
			PreviousHash: zeroHash,
			Hash:         zeroHash,
			BlockHash:    nil,
			SummaryValue: zeroHash,
		}
		require.ErrorIs(t, ErrBlockHashIsNil, testIR.IsValid())
	})
	t.Run("summary value hash is nil", func(t *testing.T) {
		testIR := &InputRecord{
			Version:      1,
			PreviousHash: zeroHash,
			Hash:         zeroHash,
			BlockHash:    zeroHash,
			SummaryValue: nil,
		}
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
		}
		require.EqualError(t, testIR.IsValid(), "block hash is 0H, but state hash changes")
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
		}
		require.EqualError(t, testIR.IsValid(), "state hash does not change, but block hash is 0H")
	})
	t.Run("valid input record", func(t *testing.T) {
		testIR := &InputRecord{
			Version:      1,
			PreviousHash: zeroHash,
			Hash:         zeroHash,
			BlockHash:    zeroHash,
			SummaryValue: zeroHash,
			RoundNumber:  1,
		}
		require.NoError(t, testIR.IsValid())
	})
}

func TestInputRecord_IsNil(t *testing.T) {
	var ir *InputRecord
	require.ErrorIs(t, ir.IsValid(), ErrInputRecordIsNil)
}

func TestInputRecord_AddToHasher(t *testing.T) {
	hasher := sha256.New()
	ir.AddToHasher(hasher)
	hash := hasher.Sum(nil)
	require.Equal(t, []byte{0x28, 0xb6, 0x55, 0xb7, 0x60, 0xa7, 0x33, 0x9a, 0x1a, 0x97, 0x88, 0xa, 0x52, 0x17, 0xae, 0x79, 0x87, 0x9, 0xbf, 0x29, 0xd2, 0x89, 0x9c, 0xb7, 0x46, 0x7a, 0x8e, 0xc2, 0xa4, 0x16, 0xd4, 0xe9}, hash)
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
		require.NoError(t, AssertEqualIR(irA, irB))
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
		require.EqualError(t, AssertEqualIR(irA, irB), "previous state hash is different: 010101 vs 0101")
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
		require.EqualError(t, AssertEqualIR(irA, irB), "state hash is different: 020202 vs 02020203")
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
		require.EqualError(t, AssertEqualIR(irA, irB), "block hash is different: 030303 vs ")
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
		require.EqualError(t, AssertEqualIR(irA, irB), "summary value is different: [4 4 4] vs []")
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
		require.EqualError(t, AssertEqualIR(irA, irB), "round number is different: 2 vs 1")
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
		require.EqualError(t, AssertEqualIR(irA, irB), "sum of fees is different: 33 vs 1")
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
