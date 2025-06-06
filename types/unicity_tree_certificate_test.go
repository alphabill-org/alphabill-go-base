package types

import (
	"crypto"
	"crypto/sha256"
	"testing"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	test "github.com/alphabill-org/alphabill-go-base/testutils"
	"github.com/stretchr/testify/require"
)

func TestUnicityTreeCertificate_IsValid(t *testing.T) {
	const partitionID PartitionID = 0x01010101

	t.Run("unicity tree certificate is nil", func(t *testing.T) {
		var uct *UnicityTreeCertificate = nil
		require.ErrorIs(t, uct.IsValid(2), ErrUnicityTreeCertificateIsNil)
	})

	t.Run("invalid partition identifier", func(t *testing.T) {
		uct := &UnicityTreeCertificate{
			Version:   1,
			Partition: partitionID,
			HashSteps: []*PathItem{{Key: partitionID, Hash: test.RandomBytes(32)}},
		}
		require.EqualError(t, uct.IsValid(0x01010100),
			"invalid partition identifier: expected 01010100, got 01010101")
	})

	t.Run("ok", func(t *testing.T) {
		leaf := UnicityTreeData{
			Partition:     partitionID,
			ShardTreeRoot: []byte{9, 9, 9, 9},
		}
		hasher := crypto.SHA256.New()
		abhasher := abhash.New(hasher)
		leaf.AddToHasher(abhasher)
		require.Equal(t, partitionID.Bytes(), leaf.Key())
		uct := &UnicityTreeCertificate{
			Version:   1,
			Partition: partitionID,
			HashSteps: []*PathItem{{Key: partitionID, Hash: hasher.Sum(nil)}},
		}
		require.NoError(t, uct.IsValid(partitionID))

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
			HashSteps: []*PathItem{{Key: partitionID, Hash: test.RandomBytes(32)}},
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
		HashSteps: []*PathItem{{Key: partitionID, Hash: []byte{1, 2, 3}}},
	}

	utBytes, err := ut.MarshalCBOR()
	require.NoError(t, err)
	expectedHash := sha256.Sum256(utBytes)
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
	shardConf *PartitionDescriptionRecord,
) *UnicityCertificate {
	t.Helper()

	shardConfHash := doHash(t, shardConf)
	sTree, err := CreateShardTree(ShardingScheme{}, []ShardTreeInput{
		{IR: ir, TRHash: trHash, ShardConfHash: shardConfHash},
	}, crypto.SHA256)
	require.NoError(t, err)
	stCert, err := sTree.Certificate(ShardID{})
	require.NoError(t, err)

	leaf := []*UnicityTreeData{{
		Partition:     shardConf.PartitionID,
		ShardTreeRoot: sTree.RootHash(),
	}}
	ut, err := NewUnicityTree(crypto.SHA256, leaf)
	require.NoError(t, err)
	utCert, err := ut.Certificate(shardConf.PartitionID)
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
		ShardConfHash:          shardConfHash,
		ShardTreeCertificate:   stCert,
		UnicityTreeCertificate: utCert,
		UnicitySeal:            unicitySeal,
	}
}
