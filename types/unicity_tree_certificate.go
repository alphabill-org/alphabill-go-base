package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/tree/imt"
)

var (
	ErrUnicityTreeCertificateIsNil = errors.New("unicity tree certificate is nil")
	ErrUCIsNil                     = errors.New("new UC is nil")
	ErrLastUCIsNil                 = errors.New("last UC is nil")
)

type UnicityTreeCertificate struct {
	_                        struct{}        `cbor:",toarray"`
	Version                  ABVersion       `json:"version"`
	PartitionID              PartitionID     `json:"partitionIdentifier"`
	HashSteps                []*imt.PathItem `json:"hashSteps"`
	PartitionDescriptionHash []byte          `json:"partitionDescriptionHash"`
}

type UnicityTreeData struct {
	partitionID              PartitionID
	InputRecord              *InputRecord
	PartitionDescriptionHash []byte
}

func (t *UnicityTreeData) AddToHasher(hasher hash.Hash) {
	t.InputRecord.AddToHasher(hasher)
	hasher.Write(t.PartitionDescriptionHash)
}

func (t *UnicityTreeData) Key() []byte {
	return t.partitionID.Bytes()
}

func (x *UnicityTreeCertificate) IsValid(partitionID PartitionID, systemDescriptionHash []byte) error {
	if x == nil {
		return ErrUnicityTreeCertificateIsNil
	}
	if x.PartitionID != partitionID {
		return fmt.Errorf("invalid partition identifier: expected %s, got %s", partitionID, x.PartitionID)
	}
	if !bytes.Equal(systemDescriptionHash, x.PartitionDescriptionHash) {
		return fmt.Errorf("invalid system description hash: expected %X, got %X", systemDescriptionHash, x.PartitionDescriptionHash)
	}
	return nil
}

func (x *UnicityTreeCertificate) EvalAuthPath(inputRecord *InputRecord, hashAlgorithm crypto.Hash) []byte {
	// restore the merkle path with the first hash step
	var hashSteps []*imt.PathItem
	hashSteps = append(hashSteps, x.FirstHashStep(inputRecord, hashAlgorithm))
	hashSteps = append(hashSteps, x.HashSteps...)

	// calculate root hash from the merkle path
	return imt.IndexTreeOutput(hashSteps, x.PartitionID.Bytes(), hashAlgorithm)
}

func (x *UnicityTreeCertificate) AddToHasher(hasher hash.Hash) {
	hasher.Write(x.PartitionID.Bytes())
	for _, hashStep := range x.HashSteps {
		hasher.Write(hashStep.Key)
		hasher.Write(hashStep.Hash)
	}
	hasher.Write(x.PartitionDescriptionHash)
}

// FirstHashStep restores the first hash step that was left out as an optimization
func (x *UnicityTreeCertificate) FirstHashStep(inputRecord *InputRecord, hashAlgorithm crypto.Hash) *imt.PathItem {
	leaf := UnicityTreeData{
		partitionID:              x.PartitionID,
		InputRecord:              inputRecord,
		PartitionDescriptionHash: x.PartitionDescriptionHash,
	}
	hasher := hashAlgorithm.New()
	leaf.AddToHasher(hasher)
	leafHash := hasher.Sum(nil)

	return &imt.PathItem{
		Key:  x.PartitionID.Bytes(),
		Hash: leafHash,
	}
}
