package types

import (
	"crypto"
	"crypto/sha256"
	"testing"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/stretchr/testify/require"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	test "github.com/alphabill-org/alphabill-go-base/testutils"
	"github.com/alphabill-org/alphabill-go-base/tree/imt"
)

func TestUnicityTreeCertificate_IsValid(t *testing.T) {
	const partitionID PartitionID = 0x01010101
	pdrHash := test.RandomBytes(32)

	t.Run("unicity tree certificate is nil", func(t *testing.T) {
		var uct *UnicityTreeCertificate = nil
		require.ErrorIs(t, uct.IsValid(2, pdrHash), ErrUnicityTreeCertificateIsNil)
	})

	t.Run("invalid system identifier", func(t *testing.T) {
		uct := &UnicityTreeCertificate{
			Version:   1,
			Partition: partitionID,
			HashSteps: []*imt.PathItem{{Key: partitionID.Bytes(), Hash: test.RandomBytes(32)}},
			PDRHash:   pdrHash,
		}
		require.EqualError(t, uct.IsValid(0x01010100, pdrHash),
			"invalid partition identifier: expected 01010100, got 01010101")
	})

	t.Run("invalid system description hash", func(t *testing.T) {
		uct := &UnicityTreeCertificate{
			Version:   1,
			Partition: partitionID,
			HashSteps: []*imt.PathItem{{Key: partitionID.Bytes(), Hash: test.RandomBytes(32)}},
			PDRHash:   []byte{1, 1, 1, 1},
		}
		require.EqualError(t, uct.IsValid(partitionID, []byte{1, 1, 1, 2}),
			"invalid system description hash: expected 01010102, got 01010101")
	})

	t.Run("ok", func(t *testing.T) {
		leaf := UnicityTreeData{
			Partition:     partitionID,
			ShardTreeRoot: []byte{9, 9, 9, 9},
			PDRHash:       pdrHash,
		}
		hasher := crypto.SHA256.New()
		abhasher := abhash.New(hasher)
		leaf.AddToHasher(abhasher)
		require.Equal(t, partitionID.Bytes(), leaf.Key())
		uct := &UnicityTreeCertificate{
			Version:   1,
			Partition: partitionID,
			HashSteps: []*imt.PathItem{{Key: partitionID.Bytes(), Hash: hasher.Sum(nil)}},
			PDRHash:   pdrHash,
		}
		require.NoError(t, uct.IsValid(partitionID, pdrHash))

		uctBytes, err := uct.MarshalCBOR()
		require.NoError(t, err)
		uct2 := &UnicityTreeCertificate{}
		require.NoError(t, uct2.UnmarshalCBOR(uctBytes))
		require.Equal(t, uct, uct2)
	})

	t.Run("unmarshal invalid version", func(t *testing.T) {
		uct := &UnicityTreeCertificate{
			Version:   2,
			Partition: partitionID,
			HashSteps: []*imt.PathItem{{Key: partitionID.Bytes(), Hash: test.RandomBytes(32)}},
			PDRHash:   pdrHash,
		}
		uctBytes, err := uct.MarshalCBOR()
		require.NoError(t, err)
		uct2 := &UnicityTreeCertificate{}
		require.ErrorContains(t, uct2.UnmarshalCBOR(uctBytes), "invalid version (type *types.UnicityTreeCertificate), expected 1, got 2")
	})
}

func TestUnicityTreeCertificate_Hash(t *testing.T) {
	const partitionID PartitionID = 0x01010101
	ut := &UnicityTreeCertificate{
		Version:   1,
		Partition: partitionID,
		HashSteps: []*imt.PathItem{{Key: partitionID.Bytes(), Hash: []byte{1, 2, 3}}},
		PDRHash:   []byte{1, 2, 3, 4},
	}
	expectedBytes := []byte{
		0, 0, 0, 1, // version
		1, 1, 1, 1, //identifier
		1, 1, 1, 1, 1, 2, 3, // siblings key+hash
		1, 2, 3, 4, // system description hash
	}
	expectedHash := sha256.Sum256(expectedBytes)
	// test add to hasher too
	hasher := crypto.SHA256.New()
	abhasher := abhash.New(hasher)
	ut.AddToHasher(abhasher)
	require.EqualValues(t, expectedHash[:], hasher.Sum(nil))
}

func createUnicityCertificate(
	t *testing.T,
	rootID string,
	signer abcrypto.Signer,
	ir *InputRecord,
	trHash []byte,
	pdr *PartitionDescriptionRecord,
) *UnicityCertificate {
	t.Helper()

	sTree, err := CreateShardTree(ShardingScheme{}, []ShardTreeInput{{IR: ir, TRHash: trHash}}, crypto.SHA256)
	require.NoError(t, err)
	stCert, err := sTree.Certificate(ShardID{})
	require.NoError(t, err)

	leaf := []*UnicityTreeData{{
		Partition:     pdr.PartitionIdentifier,
		ShardTreeRoot: sTree.RootHash(),
		PDRHash:       doHash(t, pdr),
	}}
	ut, err := NewUnicityTree(crypto.SHA256, leaf)
	require.NoError(t, err)
	utCert, err := ut.Certificate(pdr.PartitionIdentifier)
	require.NoError(t, err)

	unicitySeal := &UnicitySeal{
		Version:              1,
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         make([]byte, 32),
		Hash:                 ut.RootHash(),
	}
	require.NoError(t, unicitySeal.Sign(rootID, signer))

	return &UnicityCertificate{
		Version:                1,
		InputRecord:            ir,
		TRHash:                 trHash,
		ShardTreeCertificate:   stCert,
		UnicityTreeCertificate: utCert,
		UnicitySeal:            unicitySeal,
	}
}
