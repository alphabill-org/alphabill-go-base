package types

import (
	"crypto"
	"crypto/sha256"
	"testing"

	testsig "github.com/alphabill-org/alphabill-go-base/testutils/sig"
	"github.com/alphabill-org/alphabill-go-base/tree/imt"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
	"github.com/stretchr/testify/require"
)

func TestUnicityCertificate_IsValid(t *testing.T) {
	const partitionID PartitionID = 0x01010101
	sdrh := zeroHash
	signer, _ := testsig.CreateSignerAndVerifier(t)

	inputRecord := &InputRecord{
		Version:         1,
		PreviousHash:    []byte{0, 0, 1},
		Hash:            []byte{0, 0, 2},
		BlockHash:       []byte{0, 0, 3},
		SummaryValue:    []byte{0, 0, 4},
		RoundNumber:     1,
		Epoch:           0,
		SumOfEarnedFees: 20,
	}

	leaf := UnicityTreeData{
		PartitionIdentifier:      partitionID,
		InputRecord:              inputRecord,
		PartitionDescriptionHash: sdrh,
	}
	hasher := crypto.SHA256.New()
	leaf.AddToHasher(hasher)
	utLeafHash := hasher.Sum(nil)

	validUC := func(t *testing.T) *UnicityCertificate {
		seal := &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
			Timestamp:            NewTimestamp(),
			PreviousHash:         zeroHash,
			Hash:                 hexDecode(t, "C921527C96562C8146AAB0086B7DB836538BFCD96EDA92B7C4FA2A1DC4443FB3"),
		}
		require.NoError(t, seal.Sign("test", signer))

		return &UnicityCertificate{
			Version:     1,
			InputRecord: inputRecord,
			TRHash:      zeroHash,
			UnicityTreeCertificate: &UnicityTreeCertificate{Version: 1,
				PartitionIdentifier:      partitionID,
				PartitionDescriptionHash: zeroHash,
				HashSteps:                []*imt.PathItem{{Key: partitionID.Bytes(), Hash: utLeafHash}},
			},
			UnicitySeal: seal,
		}
	}

	require.NoError(t, validUC(t).IsValid(crypto.SHA256, identifier, sdrh))

	t.Run("UC is nil", func(t *testing.T) {
		var uc *UnicityCertificate
		require.EqualValues(t, 0, uc.GetRoundNumber())
		require.EqualValues(t, 0, uc.GetRootRoundNumber())
		require.Nil(t, uc.GetStateHash())
		require.ErrorIs(t, uc.Verify(nil, crypto.SHA256, 0, nil), ErrUnicityCertificateIsNil)
	})

	t.Run("invalid input record", func(t *testing.T) {
		uc := validUC(t)
		uc.InputRecord = nil
		require.EqualValues(t, 0, uc.GetRoundNumber())
		require.Nil(t, uc.GetStateHash())
		require.ErrorIs(t, uc.IsValid(crypto.SHA256, identifier, sdrh), ErrInputRecordIsNil)
	})

	t.Run("invalid uct is nil", func(t *testing.T) {
		uc := validUC(t)
		uc.UnicityTreeCertificate = nil
		require.ErrorIs(t, uc.IsValid(crypto.SHA256, identifier, sdrh), ErrUnicityTreeCertificateIsNil)
	})

	t.Run("invalid unicity seal is nil", func(t *testing.T) {
		uc := validUC(t)
		uc.UnicitySeal = nil
		require.ErrorIs(t, uc.IsValid(crypto.SHA256, identifier, sdrh), ErrUnicitySealIsNil)
	})

	t.Run("invalid root hash", func(t *testing.T) {
		uc := validUC(t)
		uc.UnicitySeal.Hash = []byte{1, 2, 3}
		require.EqualError(t, uc.IsValid(crypto.SHA256, identifier, sdrh),
			"unicity seal hash 010203 does not match with the root hash of the unicity tree C921527C96562C8146AAB0086B7DB836538BFCD96EDA92B7C4FA2A1DC4443FB3")
	})

	t.Run("version unassigned", func(t *testing.T) {
		uc := validUC(t)
		uc.Version = 0
		require.EqualError(t, uc.IsValid(crypto.SHA256, identifier, sdrh), `invalid version (type *types.UnicityCertificate)`)
	})

	t.Run("invalid TRHash", func(t *testing.T) {
		uc := validUC(t)
		uc.TRHash = nil
		require.EqualError(t, uc.IsValid(crypto.SHA256, identifier, sdrh), `invalid TRHash: expected 32 bytes, got 0 bytes`)

		uc.TRHash = make([]byte, 33)
		require.EqualError(t, uc.IsValid(crypto.SHA256, identifier, sdrh), `invalid TRHash: expected 32 bytes, got 33 bytes`)
	})
}

func TestUnicityCertificate_Verify(t *testing.T) {
	sdrh := zeroHash
	t.Run("UC is nil", func(t *testing.T) {
		uc := UnicityCertificate{Version: 1}
		require.EqualError(t, uc.Verify(nil, crypto.SHA256, 0, nil),
			"unicity certificate validation failed: input record error: input record is nil")
	})
	t.Run("tb is nil", func(t *testing.T) {
		signer, _ := testsig.CreateSignerAndVerifier(t)
		inputRecord := &InputRecord{
			Version:         1,
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			BlockHash:       []byte{0, 0, 3},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     1,
			SumOfEarnedFees: 20,
		}
		seal := &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
			Timestamp:            NewTimestamp(),
			PreviousHash:         zeroHash,
			Hash:                 hexDecode(t, "C74D4EA52F8E4D121B20AFC7A628C06F32CF56699DFF6C85676C767F439E8FF4"),
		}
		require.NoError(t, seal.Sign("test", signer))
		uc := &UnicityCertificate{
			Version:     1,
			InputRecord: inputRecord,
			TRHash:      make([]byte, 32),
			UnicityTreeCertificate: &UnicityTreeCertificate{Version: 1,
				PartitionIdentifier:      identifier,
				PartitionDescriptionHash: zeroHash,
			},
			UnicitySeal: seal,
		}
		require.EqualError(t, uc.Verify(nil, crypto.SHA256, identifier, sdrh),
			"unicity seal signature validation failed: root node info is missing")
	})
	t.Run("verify ok", func(t *testing.T) {
		signer, verifier := testsig.CreateSignerAndVerifier(t)
		inputRecord := &InputRecord{
			Version:         1,
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			BlockHash:       []byte{0, 0, 3},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     1,
			SumOfEarnedFees: 20,
		}
		seal := &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
			Timestamp:            1712524909,
			PreviousHash:         zeroHash,
			Hash:                 hexDecode(t, "C74D4EA52F8E4D121B20AFC7A628C06F32CF56699DFF6C85676C767F439E8FF4"),
		}
		require.NoError(t, seal.Sign("test", signer))
		uc := &UnicityCertificate{
			Version:     1,
			InputRecord: inputRecord,
			TRHash:      make([]byte, 32),
			UnicityTreeCertificate: &UnicityTreeCertificate{Version: 1,
				PartitionIdentifier:      identifier,
				PartitionDescriptionHash: zeroHash,
			},
			UnicitySeal: seal,
		}
		tb := NewTrustBase(t, verifier)
		require.NoError(t, uc.Verify(tb, crypto.SHA256, identifier, sdrh))
	})
}

func TestUnicityCertificate_isRepeat(t *testing.T) {
	uc := &UnicityCertificate{
		Version: 1,
		InputRecord: &InputRecord{
			Version:         1,
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			BlockHash:       []byte{0, 0, 3},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     6,
			SumOfEarnedFees: 20,
		},
		UnicitySeal: &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
		},
	}
	require.EqualValues(t, []byte{0, 0, 2}, uc.GetStateHash())
	// everything is equal, this is the same UC and not repeat
	require.False(t, isRepeat(uc, uc))
	ruc := &UnicityCertificate{
		Version:     1,
		InputRecord: uc.InputRecord.NewRepeatIR(),
		UnicitySeal: &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: uc.UnicitySeal.RootChainRoundNumber + 1,
		},
	}
	require.True(t, ruc.IsRepeat(uc))
	// now it is repeat of previous round
	require.True(t, isRepeat(uc, ruc))
	ruc.UnicitySeal.RootChainRoundNumber++
	// still is considered a repeat uc
	require.True(t, isRepeat(uc, ruc))
	// with incremented round number, not a repeat uc
	ruc.InputRecord.RoundNumber++
	require.False(t, isRepeat(uc, ruc))
	// if anything else changes, it is no longer considered repeat
	require.False(t, isRepeat(uc, &UnicityCertificate{
		Version: 1,
		InputRecord: &InputRecord{
			Version:         1,
			Hash:            []byte{0, 0, 2},
			BlockHash:       []byte{0, 0, 3},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     6,
			SumOfEarnedFees: 20,
		},
	}))
	require.False(t, isRepeat(uc, &UnicityCertificate{
		Version: 1,
		InputRecord: &InputRecord{
			Version:         1,
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			BlockHash:       []byte{0, 0, 3},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     6,
			SumOfEarnedFees: 2,
		},
	}))
	// also not if order is opposite
	require.False(t, isRepeat(ruc, uc))
}

func TestCheckNonEquivocatingCertificates(t *testing.T) {
	t.Run("err - previous UC is nil", func(t *testing.T) {
		var prevUC *UnicityCertificate = nil
		newUC := &UnicityCertificate{
			Version: 1,
			InputRecord: &InputRecord{
				Version:         1,
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{Version: 1, RootChainRoundNumber: 10},
		}
		require.ErrorIs(t, CheckNonEquivocatingCertificates(prevUC, newUC), ErrLastUCIsNil)
	})
	t.Run("err - new UC is nil", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			Version: 1,
			InputRecord: &InputRecord{
				Version:         1,
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{Version: 1, RootChainRoundNumber: 10},
		}
		var newUC *UnicityCertificate = nil
		require.ErrorIs(t, CheckNonEquivocatingCertificates(prevUC, newUC), ErrUCIsNil)
	})
	t.Run("equal UC's", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			Version: 1,
			InputRecord: &InputRecord{
				Version:         1,
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{Version: 1, RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			Version: 1,
			InputRecord: &InputRecord{
				Version:         1,
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{Version: 1, RootChainRoundNumber: 10},
		}
		require.NoError(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
	t.Run("equal round, different UC", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 5},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		require.EqualError(t, CheckNonEquivocatingCertificates(prevUC, newUC), "equivocating UC, different input records for same partition round 6")
	})
	t.Run("new is older partition round", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     5,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		require.EqualError(t, CheckNonEquivocatingCertificates(prevUC, newUC), "new certificate is from older partition round 5 than previous certificate 6")
	})
	t.Run("new is older root round", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 9},
		}
		require.EqualError(t, CheckNonEquivocatingCertificates(prevUC, newUC), "new certificate is from older root round 9 than previous certificate 10")
	})
	t.Run("round gap, new is 0H block repeating the same state as last seen", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     8,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 11},
		}
		require.EqualError(t, CheckNonEquivocatingCertificates(prevUC, newUC), "new UC extends state hash, new state hash does not change, but block is not empty")
	})
	t.Run("ok - new empty block UC", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 0},
				SummaryValue:    []byte{0, 0, 3},
				RoundNumber:     7,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 11},
		}
		require.NoError(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
	t.Run("ok - repeat UC of empty block", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 0},
				SummaryValue:    []byte{0, 0, 3},
				RoundNumber:     6,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 0},
				SummaryValue:    []byte{0, 0, 3},
				RoundNumber:     9,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 18},
		}
		require.NoError(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
	t.Run("ok - too far apart to compare", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 2},
				SummaryValue:    []byte{0, 0, 3},
				RoundNumber:     6,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{3, 3, 3},
				Hash:            []byte{4, 4, 4},
				BlockHash:       []byte{0, 0, 0},
				SummaryValue:    []byte{0, 0, 3},
				RoundNumber:     9,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 18},
		}
		require.NoError(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
	t.Run("ok - normal progress", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 3},
				BlockHash:       []byte{0, 0, 4},
				SummaryValue:    []byte{0, 0, 6},
				RoundNumber:     7,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 11},
		}
		require.NoError(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
	t.Run("error - state changes, but block hash is 0h", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 3},
				BlockHash:       []byte{0, 0, 0},
				SummaryValue:    []byte{0, 0, 6},
				RoundNumber:     7,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 11},
		}
		require.Error(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
	t.Run("ok - repeat UC of previous state (skipping some repeats between)", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 3},
				BlockHash:       []byte{0, 0, 2},
				SummaryValue:    []byte{0, 0, 6},
				RoundNumber:     8,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 16},
		}
		require.NoError(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
	t.Run("err - block hash repeats on normal progress", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 2},
				Hash:            []byte{0, 0, 3},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 6},
				RoundNumber:     7,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 11},
		}
		require.EqualError(t, CheckNonEquivocatingCertificates(prevUC, newUC), "new certificate repeats previous block hash")
	})
	t.Run("err - next round does not extend from previous state", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 3},
				BlockHash:       []byte{0, 0, 4},
				SummaryValue:    []byte{0, 0, 6},
				RoundNumber:     7,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 11},
		}
		require.EqualError(t, CheckNonEquivocatingCertificates(prevUC, newUC), "new certificate does not extend previous state hash")
	})
	t.Run("err - extending from same state, but ", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 3},
				BlockHash:       []byte{0, 0, 4},
				SummaryValue:    []byte{0, 0, 6},
				RoundNumber:     7,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 11},
		}
		require.EqualError(t, CheckNonEquivocatingCertificates(prevUC, newUC), "new certificate does not extend previous state hash")
	})
	t.Run("ok - too far apart to compare (can only check block hash)", func(t *testing.T) {
		prevUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 1},
				Hash:            []byte{0, 0, 2},
				BlockHash:       []byte{0, 0, 3},
				SummaryValue:    []byte{0, 0, 4},
				RoundNumber:     6,
				SumOfEarnedFees: 2,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 10},
		}
		newUC := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash:    []byte{0, 0, 5},
				Hash:            []byte{0, 0, 6},
				BlockHash:       []byte{0, 0, 4},
				SummaryValue:    []byte{0, 0, 2},
				RoundNumber:     9,
				SumOfEarnedFees: 1,
			},
			UnicitySeal: &UnicitySeal{RootChainRoundNumber: 15},
		}
		require.NoError(t, CheckNonEquivocatingCertificates(prevUC, newUC))
	})
}

func TestUCHash(t *testing.T) {
	uc := &UnicityCertificate{
		Version: 1,
		InputRecord: &InputRecord{
			Version:         1,
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			BlockHash:       []byte{0, 0, 3},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     6,
			SumOfEarnedFees: 20,
		},
		UnicityTreeCertificate: &UnicityTreeCertificate{Version: 1,
			PartitionIdentifier:      identifier,
			PartitionDescriptionHash: []byte{1, 2, 3, 4},
			HashSteps:                []*imt.PathItem{{Key: identifier.Bytes(), Hash: []byte{1, 2, 3}}},
		},
		UnicitySeal: &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
			Timestamp:            9,
			PreviousHash:         []byte{1, 2, 3},
			Hash:                 []byte{2, 3, 4},
			Signatures:           map[string][]byte{"1": {1, 1, 1}},
		},
	}
	// serialize manually
	expectedBytes := []byte{
		0, 0, 0, 1, // UC: version
		0, 0, 0, 1, // IR: version
		0, 0, 1, // IR: previous hash
		0, 0, 2, // IR: hash
		0, 0, 3, // IR: block hash
		0, 0, 4, // IR: summary hash
		0, 0, 0, 0, 0, 0, 0, 6, // IR: round
		0, 0, 0, 0, 0, 0, 0, 0, // IR: epoch
		0, 0, 0, 0, 0, 0, 0, 20, // IR: sum of fees
		0, 0, 0, 1, // UT: version
		1, 1, 1, 1, // UT: identifier
		1, 1, 1, 1, 1, 2, 3, // UT: siblings key+hash
		1, 2, 3, 4, // UT: system description hash
		0, 0, 0, 1, // US: version
		0, 0, 0, 0, 0, 0, 0, 1, // US: root round
		0, 0, 0, 0, 0, 0, 0, 9, // US: timestamp
		1, 2, 3, // US: previous hash
		2, 3, 4, // US: hash
		'1', 1, 1, 1, // US: signature
	}
	expectedHash := sha256.Sum256(expectedBytes)
	require.EqualValues(t, expectedHash[:], uc.Hash(crypto.SHA256))
}

func TestUnicityCertificate_GetPreviousStateHash(t *testing.T) {
	t.Run("UC is nil", func(t *testing.T) {
		var x *UnicityCertificate = nil
		require.Nil(t, x.GetPreviousStateHash())
	})
	t.Run("IR is nil", func(t *testing.T) {
		x := &UnicityCertificate{}
		require.Nil(t, x.GetPreviousStateHash())
	})
	t.Run("hash value", func(t *testing.T) {
		x := &UnicityCertificate{
			InputRecord: &InputRecord{
				PreviousHash: []byte{1, 2, 3},
			},
		}
		require.Equal(t, []byte{1, 2, 3}, x.GetPreviousStateHash())
	})
}

func TestUnicityCertificate_GetFeeSum(t *testing.T) {
	t.Run("UC is nil", func(t *testing.T) {
		var x *UnicityCertificate = nil
		require.EqualValues(t, 0, x.GetFeeSum())
	})
	t.Run("IR is nil", func(t *testing.T) {
		x := &UnicityCertificate{}
		require.EqualValues(t, 0, x.GetFeeSum())
	})
	t.Run("hash value", func(t *testing.T) {
		x := &UnicityCertificate{
			InputRecord: &InputRecord{
				SumOfEarnedFees: 10,
			},
		}
		require.EqualValues(t, 10, x.GetFeeSum())
	})
}

func TestUnicityCertificate_GetSummaryValue(t *testing.T) {
	t.Run("UC is nil", func(t *testing.T) {
		var x *UnicityCertificate = nil
		require.Nil(t, x.GetSummaryValue())
	})
	t.Run("IR is nil", func(t *testing.T) {
		x := &UnicityCertificate{}
		require.Nil(t, x.GetSummaryValue())
	})
	t.Run("hash value", func(t *testing.T) {
		x := &UnicityCertificate{
			InputRecord: &InputRecord{
				SummaryValue: []byte{1, 2, 3},
			},
		}
		require.EqualValues(t, []byte{1, 2, 3}, x.GetSummaryValue())
	})
}

func TestUnicityCertificate_GetRootRoundNumber(t *testing.T) {
	t.Run("UC is nil", func(t *testing.T) {
		var x *UnicityCertificate = nil
		require.EqualValues(t, 0, x.GetRootRoundNumber())
	})
	t.Run("UC seal is nil", func(t *testing.T) {
		x := &UnicityCertificate{}
		require.EqualValues(t, 0, x.GetRootRoundNumber())
	})
	t.Run("returns round", func(t *testing.T) {
		x := &UnicityCertificate{
			UnicitySeal: &UnicitySeal{
				RootChainRoundNumber: 1,
			}}
		require.EqualValues(t, 1, x.GetRootRoundNumber())
	})
}

func Test_Cbor(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		ucA := UnicityCertificate{
			Version:                1,
			InputRecord:            &InputRecord{Version: 1},
			TRHash:                 []byte{1, 2, 3, 4, 5},
			UnicityTreeCertificate: &UnicityTreeCertificate{Version: 1},
			UnicitySeal: &UnicitySeal{
				Version:    1,
				Signatures: SignatureMap{"A1": []byte{10, 1}},
			},
		}
		buf, err := ucA.MarshalCBOR()
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		var ucB UnicityCertificate
		require.NoError(t, ucB.UnmarshalCBOR(buf))
		require.Equal(t, ucA, ucB, "expected to get the same UC back")
	})

	t.Run("version 1", func(t *testing.T) {
		// if this tests fails the number of fields (or type) in the UC has changed,
		// must do a version change? ucData is CBOR of zero value, ie
		//uc := &UnicityCertificate{InputRecord: &InputRecord{}, TRHash: []byte{1}, UnicityTreeCertificate: &UnicityTreeCertificate{}, UnicitySeal: &UnicitySeal{}}
		//_ucData, _ := uc.MarshalCBOR()
		//fmt.Printf("ucData: 0x%X\n", _ucData)
		ucData, err := hex.Decode([]byte("0xD903EF8501D903F08801F6F6F6F60000004101D903F6840000F6F6D903E986010000F6F64180"))
		require.NoError(t, err)

		uc1 := &UnicityCertificate{}
		require.NoError(t, uc1.UnmarshalCBOR(ucData))

		uc2 := UnicityCertificate{}
		require.NoError(t, Cbor.Unmarshal(ucData, &uc2))

		require.Equal(t, uc1, &uc2)
	})
}
