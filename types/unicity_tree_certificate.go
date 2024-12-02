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
	PDRHash   hex.Bytes       `json:"partitionDescriptionHash"`
	HashSteps []*imt.PathItem `json:"hashSteps"`
}

type UnicityTreeData struct {
	_             struct{} `cbor:",toarray"`
	Partition     PartitionID
	ShardTreeRoot []byte // root hash of the partition shard tree
	PDRHash       []byte // PartitionDescriptionRecord hash
}

func (t *UnicityTreeData) AddToHasher(hasher abhash.Hasher) {
	hasher.Write(t.ShardTreeRoot)
	hasher.Write(t.PDRHash)
}

func (t *UnicityTreeData) Key() []byte {
	return t.Partition.Bytes()
}

func (utc *UnicityTreeCertificate) IsValid(partition PartitionID, pdrHash []byte) error {
	if utc == nil {
		return ErrUnicityTreeCertificateIsNil
	}
	if utc.Version != 1 {
		return ErrInvalidVersion(utc)
	}
	if utc.Partition != partition {
		return fmt.Errorf("invalid partition identifier: expected %s, got %s", partition, utc.Partition)
	}
	if !bytes.Equal(pdrHash, utc.PDRHash) {
		return fmt.Errorf("invalid partition description hash: expected %X, got %X", pdrHash, utc.PDRHash)
	}
	return nil
}

/*
EvalAuthPath aka Compute Unicity Tree Certificate.

The shardTreeRoot is output of the CompShardTreeCert function.
*/
func (utc *UnicityTreeCertificate) EvalAuthPath(shardTreeRoot []byte, hashAlgorithm crypto.Hash) ([]byte, error) {
	// restore the merkle path with the first hash step
	hasher := abhash.New(hashAlgorithm.New())
	(&UnicityTreeData{
		Partition:     utc.Partition,
		ShardTreeRoot: shardTreeRoot,
		PDRHash:       utc.PDRHash,
	}).AddToHasher(hasher)
	h, err := hasher.Sum()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate leaf hash: %w", err)
	}
	hashSteps := append([]*imt.PathItem{{Key: utc.Partition.Bytes(), Hash: h}}, utc.HashSteps...)

	// calculate root hash from the merkle path
	return imt.IndexTreeOutput(hashSteps, utc.Partition.Bytes(), hashAlgorithm)
}

func (utc *UnicityTreeCertificate) AddToHasher(hasher abhash.Hasher) {
	hasher.Write(utc)
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
