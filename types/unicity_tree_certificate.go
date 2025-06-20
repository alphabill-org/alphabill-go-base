package types

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/cbor"
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
	_         struct{}    `cbor:",toarray"`
	Version   ABVersion   `json:"version"`
	Partition PartitionID `json:"partitionId"`
	HashSteps []*PathItem `json:"hashSteps"`
}

type UnicityTreeData struct {
	_             struct{} `cbor:",toarray"`
	Partition     PartitionID
	ShardTreeRoot []byte // root hash of the partition shard tree
}

type PathItem struct {
	_    struct{} `cbor:",toarray"`
	Key  PartitionID
	Hash hex.Bytes
}

func (t *UnicityTreeData) AddToHasher(hasher abhash.Hasher) {
	hasher.Write(t.ShardTreeRoot)
}

func (t *UnicityTreeData) Key() []byte {
	return t.Partition.Bytes()
}

func (utc *UnicityTreeCertificate) IsValid(partition PartitionID) error {
	if utc == nil {
		return ErrUnicityTreeCertificateIsNil
	}
	if utc.Version != 1 {
		return ErrInvalidVersion(utc)
	}
	if utc.Partition != partition {
		return fmt.Errorf("invalid partition identifier: expected %s, got %s", partition, utc.Partition)
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
	}).AddToHasher(hasher)
	h, err := hasher.Sum()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate leaf hash: %w", err)
	}
	hashSteps := []*imt.PathItem{imt.NewPathItem(utc.Partition.Bytes(), h)}
	for _, s := range utc.HashSteps {
		hashSteps = append(hashSteps, s.ToIMTPathItem())
	}

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
	return cbor.MarshalTaggedValue(UnicityTreeCertificateTag, (*alias)(utc))
}

func (utc *UnicityTreeCertificate) UnmarshalCBOR(data []byte) error {
	type alias UnicityTreeCertificate
	if err := cbor.UnmarshalTaggedValue(UnicityTreeCertificateTag, data, (*alias)(utc)); err != nil {
		return err
	}
	return EnsureVersion(utc, utc.Version, 1)
}

func (p *PathItem) ToIMTPathItem() *imt.PathItem {
	return imt.NewPathItem(p.Key.Bytes(), p.Hash)
}
