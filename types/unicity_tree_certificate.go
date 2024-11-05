package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/tree/imt"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var (
	ErrUnicityTreeCertificateIsNil = errors.New("unicity tree certificate is nil")
	ErrUCIsNil                     = errors.New("new UC is nil")
	ErrLastUCIsNil                 = errors.New("last UC is nil")
)

type UnicityTreeCertificate struct {
	_         struct{}        `cbor:",toarray"`
	Version   ABVersion       `json:"version"`
	Partition PartitionID     `json:"partitionIdentifier"`
	HashSteps []*imt.PathItem `json:"hashSteps"`
	PDRHash   hex.Bytes       `json:"partitionDescriptionHash"`
}

type UnicityTreeData struct {
	Partition     PartitionID
	ShardTreeRoot []byte // root hash of the partition shard tree
	PDRHash       []byte // PartitionDescriptionRecord hash
}

func (t *UnicityTreeData) AddToHasher(hasher hash.Hash) {
	hasher.Write(t.ShardTreeRoot)
	hasher.Write(t.PDRHash)
}

func (t *UnicityTreeData) Key() []byte {
	return t.Partition.Bytes()
}

func (utc *UnicityTreeCertificate) IsValid(partition PartitionID, systemDescriptionHash []byte) error {
	if utc == nil {
		return ErrUnicityTreeCertificateIsNil
	}
	if utc.Partition != partition {
		return fmt.Errorf("invalid partition identifier: expected %s, got %s", partition, utc.Partition)
	}
	if !bytes.Equal(systemDescriptionHash, utc.PDRHash) {
		return fmt.Errorf("invalid system description hash: expected %X, got %X", systemDescriptionHash, utc.PDRHash)
	}
	return nil
}

/*
EvalAuthPath aka Compute Unicity Tree Certificate.

The shardTreeRoot is output of the CompShardTreeCert function.
*/
func (utc *UnicityTreeCertificate) EvalAuthPath(shardTreeRoot []byte, hashAlgorithm crypto.Hash) []byte {
	// restore the merkle path with the first hash step
	h := hashAlgorithm.New()
	(&UnicityTreeData{
		Partition:     utc.Partition,
		ShardTreeRoot: shardTreeRoot,
		PDRHash:       utc.PDRHash,
	}).AddToHasher(h)
	hashSteps := append([]*imt.PathItem{{Key: utc.Partition.Bytes(), Hash: h.Sum(nil)}}, utc.HashSteps...)

	// calculate root hash from the merkle path
	return imt.IndexTreeOutput(hashSteps, utc.Partition.Bytes(), hashAlgorithm)
}

func (utc *UnicityTreeCertificate) AddToHasher(hasher hash.Hash) {
	hasher.Write(utc.Partition.Bytes())
	for _, hashStep := range utc.HashSteps {
		hasher.Write(hashStep.Key)
		hasher.Write(hashStep.Hash)
	}
	hasher.Write(utc.PDRHash)
}
