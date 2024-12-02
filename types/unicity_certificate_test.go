package types

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	testsig "github.com/alphabill-org/alphabill-go-base/testutils/sig"
	"github.com/alphabill-org/alphabill-go-base/tree/imt"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

func TestUnicityCertificate_IsValid(t *testing.T) {
	const partitionID PartitionID = 0x01010101
	pdrh := zeroHash
	trHash := zeroHash
	signer, _ := testsig.CreateSignerAndVerifier(t)

	inputRecord := &InputRecord{
		Version:         1,
		PreviousHash:    []byte{0, 0, 1},
		Hash:            []byte{0, 0, 2},
		BlockHash:       []byte{0, 0, 3},
		SummaryValue:    []byte{0, 0, 4},
		RoundNumber:     1,
		Epoch:           0,
		Timestamp:       NewTimestamp(),
		SumOfEarnedFees: 20,
	}

	sTree, err := CreateShardTree(ShardingScheme{}, []ShardTreeInput{{IR: inputRecord, TRHash: trHash}}, crypto.SHA256)
	require.NoError(t, err)
	stCert, err := sTree.Certificate(ShardID{})
	require.NoError(t, err)

	leaf := []*UnicityTreeData{{
		Partition:     partitionID,
		ShardTreeRoot: sTree.RootHash(),
		PDRHash:       pdrh,
	}}
	ut, err := NewUnicityTree(crypto.SHA256, leaf)
	require.NoError(t, err)
	utCert, err := ut.Certificate(partitionID)
	require.NoError(t, err)

	validUC := func(t *testing.T) *UnicityCertificate {
		seal := &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
			Timestamp:            NewTimestamp(),
			PreviousHash:         zeroHash,
			Hash:                 ut.RootHash(),
		}
		require.NoError(t, seal.Sign("test", signer))

		return &UnicityCertificate{
			Version:                1,
			InputRecord:            inputRecord,
			TRHash:                 trHash,
			ShardTreeCertificate:   stCert,
			UnicityTreeCertificate: utCert,
			UnicitySeal:            seal,
		}
	}

	require.NoError(t, validUC(t).IsValid(crypto.SHA256, partitionID, pdrh))

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
		require.ErrorIs(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), ErrInputRecordIsNil)
	})

	t.Run("invalid UnicityTreeCertificate", func(t *testing.T) {
		uc := validUC(t)
		uc.UnicityTreeCertificate = nil
		require.ErrorIs(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), ErrUnicityTreeCertificateIsNil)
	})

	t.Run("invalid unicity seal", func(t *testing.T) {
		uc := validUC(t)
		uc.UnicitySeal = nil
		require.ErrorIs(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), ErrUnicitySealIsNil)
	})

	t.Run("invalid version", func(t *testing.T) {
		uc := validUC(t)
		uc.Version = 0
		require.EqualError(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), `invalid version (type *types.UnicityCertificate)`)

		uc.Version = 2
		require.EqualError(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), `invalid version (type *types.UnicityCertificate)`)
	})

	t.Run("invalid TRHash", func(t *testing.T) {
		uc := validUC(t)
		uc.TRHash = nil
		require.EqualError(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), `invalid TRHash: expected 32 bytes, got 0 bytes`)

		uc.TRHash = make([]byte, 33)
		require.EqualError(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), `invalid TRHash: expected 32 bytes, got 33 bytes`)
	})

	t.Run("invalid shard tree cert", func(t *testing.T) {
		uc := validUC(t)
		uc.ShardTreeCertificate.Shard = ShardID{bits: []byte{0}, length: 1}
		require.EqualError(t, uc.IsValid(crypto.SHA256, partitionID, pdrh), `invalid shard tree certificate: shard ID is 1 bits but got 0 sibling hashes`)
	})
}

func TestUnicityCertificate_Verify(t *testing.T) {
	sid0, sid1 := ShardID{}.Split()
	pdr := PartitionDescriptionRecord{
		Version:             1,
		PartitionIdentifier: 0x0f0f0f0f,
		TypeIdLen:           8,
		UnitIdLen:           256,
		Shards:              ShardingScheme{sid0, sid1},
	}
	pdrHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)

	trHash0 := bytes.Repeat([]byte{10}, 32)
	trHash1 := bytes.Repeat([]byte{11}, 32)

	signer, verifier := testsig.CreateSignerAndVerifier(t)
	tb := NewTrustBase(t, verifier)

	// must use const timestamp to have deterministic UC hash
	const curTimestamp uint64 = 1731504540

	ir0 := InputRecord{
		Version:         1,
		PreviousHash:    []byte{0, 0, 1},
		Hash:            []byte{0, 0, 2},
		BlockHash:       []byte{0, 0, 3},
		SummaryValue:    []byte{0, 0, 4},
		Timestamp:       curTimestamp,
		RoundNumber:     1,
		Epoch:           0,
		SumOfEarnedFees: 20,
	}
	ir1 := ir0
	ir1.RoundNumber = 900

	sTree, err := CreateShardTree(
		pdr.Shards,
		[]ShardTreeInput{
			{Shard: sid0, IR: &ir0, TRHash: trHash0},
			{Shard: sid1, IR: &ir1, TRHash: trHash1},
		},
		crypto.SHA256)
	require.NoError(t, err)

	ut, err := NewUnicityTree(crypto.SHA256, []*UnicityTreeData{{
		Partition:     pdr.PartitionIdentifier,
		ShardTreeRoot: sTree.RootHash(),
		PDRHash:       pdrHash,
	}})
	require.NoError(t, err)
	utCert, err := ut.Certificate(pdr.PartitionIdentifier)
	require.NoError(t, err)

	validUC := func(t *testing.T, sid ShardID, ir *InputRecord, trHash []byte) *UnicityCertificate {
		stCert, err := sTree.Certificate(sid)
		require.NoError(t, err)

		seal := &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
			Timestamp:            NewTimestamp(),
			PreviousHash:         zeroHash,
			Hash:                 ut.RootHash(),
		}
		require.NoError(t, seal.Sign("test", signer))

		return &UnicityCertificate{
			Version:                1,
			InputRecord:            ir,
			TRHash:                 trHash,
			ShardTreeCertificate:   stCert,
			UnicityTreeCertificate: utCert,
			UnicitySeal:            seal,
		}
	}

	require.NoError(t, validUC(t, sid0, &ir0, trHash0).Verify(tb, crypto.SHA256, pdr.PartitionIdentifier, pdrHash))
	require.NoError(t, validUC(t, sid1, &ir1, trHash1).Verify(tb, crypto.SHA256, pdr.PartitionIdentifier, pdrHash))

	t.Run("IsValid", func(t *testing.T) {
		// check that IsValid is called
		uc := UnicityCertificate{Version: 1}
		require.EqualError(t, uc.Verify(nil, crypto.SHA256, 0, nil),
			"invalid unicity certificate: invalid input record: input record is nil")
	})

	t.Run("tb is nil", func(t *testing.T) {
		uc := validUC(t, sid0, &ir0, trHash0)
		require.EqualError(t, uc.Verify(nil, crypto.SHA256, pdr.PartitionIdentifier, pdrHash), "verifying unicity seal: root node info is missing")
	})

	t.Run("invalid root hash", func(t *testing.T) {
		uc := validUC(t, sid0, &ir0, trHash0)
		uc.UnicitySeal.Hash = []byte{1, 2, 3}
		require.EqualError(t, uc.Verify(tb, crypto.SHA256, pdr.PartitionIdentifier, pdrHash),
			"unicity seal hash 010203 does not match with the root hash of the unicity tree AA05FEF642727D2A88B4AB8D863EA5D62173751231DC96BC0AFD8DB812A402F0")
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
	checkIsRepeat(t, uc, uc, false)
	ruc := &UnicityCertificate{
		Version:     1,
		InputRecord: uc.InputRecord.NewRepeatIR(),
		UnicitySeal: &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: uc.UnicitySeal.RootChainRoundNumber + 1,
		},
	}
	// now it is repeat of previous round
	checkIsRepeat(t, uc, ruc, true)
	ruc.UnicitySeal.RootChainRoundNumber++
	// still is considered a repeat uc
	checkIsRepeat(t, uc, ruc, true)
	// with incremented round number, not a repeat uc
	ruc.InputRecord.RoundNumber++
	checkIsRepeat(t, uc, ruc, false)
	// if anything else changes, it is no longer considered repeat
	checkIsRepeat(t, uc, &UnicityCertificate{
		Version: 1,
		InputRecord: &InputRecord{
			Version:         1,
			Hash:            []byte{0, 0, 2},
			BlockHash:       []byte{0, 0, 3},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     6,
			SumOfEarnedFees: 20,
		},
	}, false)
	checkIsRepeat(t, uc, &UnicityCertificate{
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
	}, false)
	// also not if order is opposite
	checkIsRepeat(t, ruc, uc, false)
}

func checkIsRepeat(t *testing.T, prevUC, newUC *UnicityCertificate, expected bool) {
	t.Helper()
	b, err := isRepeat(prevUC, newUC)
	require.NoError(t, err)
	require.Equal(t, expected, b)
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

func Test_UnicityCertificate_Hash(t *testing.T) {
	const partitionID PartitionID = 0x01010101
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
			Timestamp:       31,
		},
		UnicityTreeCertificate: &UnicityTreeCertificate{
			Version:   1,
			Partition: partitionID,
			PDRHash:   []byte{1, 2, 3, 4},
			HashSteps: []*imt.PathItem{{Key: partitionID.Bytes(), Hash: []byte{1, 2, 3}}},
		},
		UnicitySeal: &UnicitySeal{
			Version:              1,
			RootChainRoundNumber: 1,
			Timestamp:            9,
			PreviousHash:         []byte{1, 2, 3},
			Hash:                 []byte{2, 3, 4},
			Signatures:           map[string]hex.Bytes{"1": {1, 1, 1}},
		},
	}

	ucBytes, err := uc.MarshalCBOR()
	require.NoError(t, err)
	expectedHash := sha256.Sum256(ucBytes)

	require.EqualValues(t, expectedHash[:], doHash(t, uc))
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

func Test_UnicityCertificate_Cbor(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		ucA := UnicityCertificate{
			Version:                1,
			InputRecord:            &InputRecord{Version: 1},
			TRHash:                 []byte{1, 2, 3, 4, 5},
			ShardTreeCertificate:   ShardTreeCertificate{Shard: ShardID{}},
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
		ucData, err := hex.Decode([]byte("0xD903EF8601D903F089010000F6F6F600F6004101824180F6D903F6840100F6F6D903E986010000F6F6F6"))
		require.NoError(t, err)

		uc1 := &UnicityCertificate{}
		require.NoError(t, uc1.UnmarshalCBOR(ucData))

		uc2 := UnicityCertificate{}
		require.NoError(t, Cbor.Unmarshal(ucData, &uc2))

		require.Equal(t, uc1, &uc2)
	})

	t.Run("unmarshal invalid version", func(t *testing.T) {
		uc := &UnicityCertificate{Version: 2, InputRecord: &InputRecord{}, TRHash: []byte{1}, UnicityTreeCertificate: &UnicityTreeCertificate{}, UnicitySeal: &UnicitySeal{}}
		ucData, err := uc.MarshalCBOR()
		require.NoError(t, err)

		uc2 := UnicityCertificate{}
		require.ErrorContains(t, uc2.UnmarshalCBOR(ucData), "invalid version (type *types.UnicityCertificate), expected 1, got 2")
	})
}
