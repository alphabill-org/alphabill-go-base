package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/tree/imt"
)

var ErrUnicityTreeCertificateIsNil = errors.New("unicity tree certificate is nil")
var errUCIsNil = errors.New("new UC is nil")
var errLastUCIsNil = errors.New("last UC is nil")

type UnicityTreeCertificate struct {
	_                        struct{}        `cbor:",toarray"`
	SystemIdentifier         SystemID        `json:"system_identifier,omitempty"`
	SiblingHashes            []*imt.PathItem `json:"sibling_hashes,omitempty"`
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

func (x *UnicityTreeCertificate) IsValid(ir *InputRecord, systemIdentifier SystemID, systemDescriptionHash []byte, hashAlgorithm crypto.Hash) error {
	if x == nil {
		return ErrUnicityTreeCertificateIsNil
	}
	if x.SystemIdentifier != systemIdentifier {
		return fmt.Errorf("invalid system identifier: expected %s, got %s", systemIdentifier, x.SystemIdentifier)
	}
	if !bytes.Equal(systemDescriptionHash, x.PartitionDescriptionHash) {
		return fmt.Errorf("invalid system description hash: expected %X, got %X", systemDescriptionHash, x.PartitionDescriptionHash)
	}
	if len(x.SiblingHashes) == 0 {
		return fmt.Errorf("error sibling hash chain is empty")
	}
	if !bytes.Equal(x.SiblingHashes[0].Key, x.SystemIdentifier.Bytes()) {
		return fmt.Errorf("error invalid leaf key: expected %X got %X", x.SystemIdentifier.Bytes(), x.SiblingHashes[0].Key)
	}
	leaf := UnicityTreeData{
		SystemIdentifier:         x.SystemIdentifier,
		InputRecord:              ir,
		PartitionDescriptionHash: x.PartitionDescriptionHash,
	}
	hasher := hashAlgorithm.New()
	leaf.AddToHasher(hasher)
	dataHash := hasher.Sum(nil)
	if !bytes.Equal(x.SiblingHashes[0].Hash, dataHash) {
		return fmt.Errorf("error invalid data hash: expected %X got %X", x.SiblingHashes[0].Hash, dataHash)
	}
	return nil
}

func (x *UnicityTreeCertificate) EvalAuthPath(hashAlgorithm crypto.Hash) []byte {
	// calculate root hash from the merkle path
	return imt.IndexTreeOutput(x.SiblingHashes, x.SystemIdentifier.Bytes(), hashAlgorithm)
}

func (x *UnicityTreeCertificate) AddToHasher(hasher hash.Hash) {
	hasher.Write(x.SystemIdentifier.Bytes())
	for _, siblingHash := range x.SiblingHashes {
		hasher.Write(siblingHash.Key)
		hasher.Write(siblingHash.Hash)
	}
	hasher.Write(x.PartitionDescriptionHash)
}
