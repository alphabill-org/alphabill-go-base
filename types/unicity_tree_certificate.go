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
	SystemIdentifier         SystemID        `json:"system_identifier,omitempty"`
	PartitionDescriptionHash []byte          `json:"partition_description_hash,omitempty"`
	HashSteps                []*imt.PathItem `json:"hash_steps,omitempty"`
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
	if x.SystemIdentifier != systemIdentifier {
		return fmt.Errorf("invalid system identifier: expected %s, got %s", systemIdentifier, x.SystemIdentifier)
	}
	if !bytes.Equal(systemDescriptionHash, x.PartitionDescriptionHash) {
		return fmt.Errorf("invalid system description hash: expected %X, got %X", systemDescriptionHash, x.PartitionDescriptionHash)
	}
	return nil
}

func (x *UnicityTreeCertificate) EvalAuthPath(firstStep *imt.PathItem, hashAlgorithm crypto.Hash) []byte {
	// restore the merkle path with the first hash step
	var hashSteps []*imt.PathItem
	hashSteps = append(hashSteps, firstStep)
	hashSteps = append(hashSteps, x.HashSteps...)

	// calculate root hash from the merkle path
	return imt.IndexTreeOutput(hashSteps, x.SystemIdentifier.Bytes(), hashAlgorithm)
}

func (x *UnicityTreeCertificate) AddToHasher(hasher hash.Hash) {
	hasher.Write(x.SystemIdentifier.Bytes())
	for _, hashStep := range x.HashSteps {
		hasher.Write(hashStep.Key)
		hasher.Write(hashStep.Hash)
	}
	hasher.Write(x.PartitionDescriptionHash)
}
