package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/tree/imt"
	"github.com/alphabill-org/alphabill-go-base/util"
)

var (
	ErrUnicityTreeCertificateIsNil = errors.New("unicity tree certificate is nil")
	ErrUCIsNil                     = errors.New("new UC is nil")
	ErrLastUCIsNil                 = errors.New("last UC is nil")
)

type UnicityTreeCertificate struct {
	_                        struct{}        `cbor:",toarray"`
	Version                  ABVersion       `json:"version,omitempty"`
	SystemIdentifier         SystemID        `json:"system_identifier,omitempty"`
	HashSteps                []*imt.PathItem `json:"hash_steps,omitempty"`
	PartitionDescriptionHash []byte          `json:"partition_description_hash,omitempty"`
}

type UnicityTreeData struct {
	SystemIdentifier         SystemID
	InputRecord              *InputRecord
	PartitionDescriptionHash []byte
}

func (t *UnicityTreeData) AddToHasher(hasher hash.Hash) {
	t.InputRecord.AddToHasher(hasher)
	hasher.Write(t.PartitionDescriptionHash)
}

func (t *UnicityTreeData) Key() []byte {
	return t.SystemIdentifier.Bytes()
}

func (x *UnicityTreeCertificate) IsValid(systemIdentifier SystemID, systemDescriptionHash []byte) error {
	if x == nil {
		return ErrUnicityTreeCertificateIsNil
	}
	if x.Version == 0 {
		return ErrInvalidVersion(x)
	}
	if x.SystemIdentifier != systemIdentifier {
		return fmt.Errorf("invalid system identifier: expected %s, got %s", systemIdentifier, x.SystemIdentifier)
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
	return imt.IndexTreeOutput(hashSteps, x.SystemIdentifier.Bytes(), hashAlgorithm)
}

func (x *UnicityTreeCertificate) AddToHasher(hasher hash.Hash) {
	hasher.Write(util.Uint32ToBytes(x.Version))
	hasher.Write(x.SystemIdentifier.Bytes())
	for _, hashStep := range x.HashSteps {
		hasher.Write(hashStep.Key)
		hasher.Write(hashStep.Hash)
	}
	hasher.Write(x.PartitionDescriptionHash)
}

// FirstHashStep restores the first hash step that was left out as an optimization
func (x *UnicityTreeCertificate) FirstHashStep(inputRecord *InputRecord, hashAlgorithm crypto.Hash) *imt.PathItem {
	leaf := UnicityTreeData{
		SystemIdentifier:         x.SystemIdentifier,
		InputRecord:              inputRecord,
		PartitionDescriptionHash: x.PartitionDescriptionHash,
	}
	hasher := hashAlgorithm.New()
	leaf.AddToHasher(hasher)
	leafHash := hasher.Sum(nil)

	return &imt.PathItem{
		Key:  x.SystemIdentifier.Bytes(),
		Hash: leafHash,
	}
}

func (x *UnicityTreeCertificate) GetVersion() ABVersion {
	if x != nil && x.Version > 0 {
		return x.Version
	}
	return 0
}

func (x *UnicityTreeCertificate) MarshalCBOR() ([]byte, error) {
	type alias UnicityTreeCertificate
	if x.Version == 0 {
		x.Version = x.GetVersion()
	}
	return Cbor.MarshalTaggedValue(UnicityTreeCertificateTag, (*alias)(x))
}

func (x *UnicityTreeCertificate) UnmarshalCBOR(data []byte) error {
	type alias UnicityTreeCertificate
	return Cbor.UnmarshalTaggedValue(UnicityTreeCertificateTag, data, (*alias)(x))
}
