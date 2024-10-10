package types

import (
	gocrypto "crypto"
	"crypto/sha256"
	"testing"

	"github.com/alphabill-org/alphabill-go-base/crypto"
	test "github.com/alphabill-org/alphabill-go-base/testutils"
	"github.com/alphabill-org/alphabill-go-base/tree/imt"
	"github.com/stretchr/testify/require"
)

const identifier SystemID = 0x01010101

func TestUnicityTreeCertificate_IsValid(t *testing.T) {
	t.Run("unicity tree certificate is nil", func(t *testing.T) {
		var uct *UnicityTreeCertificate = nil
		require.ErrorIs(t, uct.IsValid(SystemID(2), test.RandomBytes(32)), ErrUnicityTreeCertificateIsNil)
	})
	t.Run("invalid system identifier", func(t *testing.T) {
		uct := &UnicityTreeCertificate{Version: 1,
			SystemIdentifier:         identifier,
			HashSteps:                []*imt.PathItem{{Key: identifier.Bytes(), Hash: test.RandomBytes(32)}},
			PartitionDescriptionHash: zeroHash,
		}
		require.EqualError(t, uct.IsValid(0x01010100, test.RandomBytes(32)),
			"invalid system identifier: expected 01010100, got 01010101")
	})
	t.Run("invalid system description hash", func(t *testing.T) {
		uct := &UnicityTreeCertificate{Version: 1,
			SystemIdentifier:         identifier,
			HashSteps:                []*imt.PathItem{{Key: identifier.Bytes(), Hash: test.RandomBytes(32)}},
			PartitionDescriptionHash: []byte{1, 1, 1, 1},
		}
		require.EqualError(t, uct.IsValid(identifier, []byte{1, 1, 1, 2}),
			"invalid system description hash: expected 01010102, got 01010101")
	})
	t.Run("ok", func(t *testing.T) {
		ir := &InputRecord{
			PreviousHash:    []byte{0, 0, 0, 0},
			Hash:            []byte{0, 0, 0, 2},
			BlockHash:       []byte{0, 0, 0, 3},
			SummaryValue:    []byte{0, 0, 0, 4},
			RoundNumber:     5,
			SumOfEarnedFees: 10,
		}
		sdrh := []byte{1, 2, 3, 4}
		leaf := UnicityTreeData{
			SystemIdentifier:         identifier,
			InputRecord:              ir,
			PartitionDescriptionHash: sdrh,
		}
		hasher := gocrypto.SHA256.New()
		leaf.AddToHasher(hasher)
		require.Equal(t, identifier.Bytes(), leaf.Key())
		var uct = &UnicityTreeCertificate{Version: 1,
			SystemIdentifier:         identifier,
			HashSteps:                []*imt.PathItem{{Key: identifier.Bytes(), Hash: hasher.Sum(nil)}},
			PartitionDescriptionHash: sdrh,
		}
		require.NoError(t, uct.IsValid(identifier, sdrh))
	})
}

func TestUnicityTreeCertificate_Serialize(t *testing.T) {
	ut := &UnicityTreeCertificate{
		Version:                  1,
		SystemIdentifier:         identifier,
		HashSteps:                []*imt.PathItem{{Key: identifier.Bytes(), Hash: []byte{1, 2, 3}}},
		PartitionDescriptionHash: []byte{1, 2, 3, 4},
	}
	expectedBytes := []byte{
		0, 0, 0, 1, // version
		1, 1, 1, 1, //identifier
		1, 1, 1, 1, 1, 2, 3, // siblings key+hash
		1, 2, 3, 4, // system description hash
	}
	expectedHash := sha256.Sum256(expectedBytes)
	// test add to hasher too
	hasher := gocrypto.SHA256.New()
	ut.AddToHasher(hasher)
	require.EqualValues(t, expectedHash[:], hasher.Sum(nil))
}

func createUnicityCertificate(
	t *testing.T,
	rootID string,
	signer crypto.Signer,
	ir *InputRecord,
	pdr *PartitionDescriptionRecord,
) *UnicityCertificate {
	t.Helper()
	leaf := &UnicityTreeData{
		SystemIdentifier:         pdr.SystemIdentifier,
		InputRecord:              ir,
		PartitionDescriptionHash: pdr.Hash(gocrypto.SHA256),
	}
	tree, err := imt.New(gocrypto.SHA256, []imt.LeafData{leaf})
	require.NoError(t, err)
	unicitySeal := &UnicitySeal{
		Version:              1,
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         make([]byte, 32),
		Hash:                 tree.GetRootHash(),
	}
	require.NoError(t, unicitySeal.Sign(rootID, signer))
	return &UnicityCertificate{
		Version:     1,
		InputRecord: ir,
		UnicityTreeCertificate: &UnicityTreeCertificate{Version: 1,
			SystemIdentifier:         pdr.SystemIdentifier,
			PartitionDescriptionHash: leaf.PartitionDescriptionHash,
		},
		UnicitySeal: unicitySeal,
	}
}
