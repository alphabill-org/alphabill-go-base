package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
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

func (t *UnicityTreeData) AddToHasher(hasher abhash.Hasher) {
	hasher.WriteRaw(t.ShardTreeRoot)
	hasher.WriteRaw(t.PDRHash)
}

func (t *UnicityTreeData) Key() []byte {
	return t.Partition.Bytes()
}

func (utc *UnicityTreeCertificate) IsValid(partition PartitionID, systemDescriptionHash []byte) error {
	if utc == nil {
		return ErrUnicityTreeCertificateIsNil
	}
	if utc.Version != 1 {
		return ErrInvalidVersion(utc)
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
	hasher := abhash.New(h)
	(&UnicityTreeData{
		Partition:     utc.Partition,
		ShardTreeRoot: shardTreeRoot,
		PDRHash:       utc.PDRHash,
	}).AddToHasher(hasher)
	hashSteps := append([]*imt.PathItem{{Key: utc.Partition.Bytes(), Hash: h.Sum(nil)}}, utc.HashSteps...)

	// calculate root hash from the merkle path
	return imt.IndexTreeOutput(hashSteps, utc.Partition.Bytes(), hashAlgorithm)
}

func (utc *UnicityTreeCertificate) AddToHasher(hasher abhash.Hasher) {
	hasher.Write(utc.Version)
	hasher.Write(utc.Partition.Bytes())
	for _, hashStep := range utc.HashSteps {
		hasher.Write(hashStep.Key)
		hasher.Write(hashStep.Hash)
	}
	hasher.Write(utc.PDRHash)
}

func (utc *UnicityTreeCertificate) GetVersion() ABVersion {
	if utc != nil && utc.Version > 0 {
		return utc.Version
	}
	return 1
}

func (utc *UnicityTreeCertificate) MarshalCBOR() ([]byte, error) {
	type alias UnicityTreeCertificate
	if utc.Version == 0 {
		utc.Version = utc.GetVersion()
	}
	return Cbor.MarshalTaggedValue(UnicityTreeCertificateTag, (*alias)(utc))
}

func (utc *UnicityTreeCertificate) UnmarshalCBOR(data []byte) error {
	type alias UnicityTreeCertificate
	if err := Cbor.UnmarshalTaggedValue(UnicityTreeCertificateTag, data, (*alias)(utc)); err != nil {
		return err
	}
	return EnsureVersion(utc, utc.Version, 1)
}
