package types

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"
)

var (
	ErrSystemDescriptionIsNil = errors.New("system description record is nil")
)

type SystemTypeDescriptor struct {
	// This is just a placeholder right now so that we can add
	// the field into the SystemDescriptionRecord - for the fast track
	// solution we do not expect to have non nil SystemTypeDescriptor
	// so the actual field list is not needed...
}

func (std *SystemTypeDescriptor) AddToHasher(h hash.Hash) {
	if std == nil {
		h.Write([]byte{0})
		return
	}
	// todo: hash field values
}

type PartitionDescriptionRecord struct {
	_                struct{} `cbor:",toarray"`
	SystemIdentifier SystemID `json:"system_identifier,omitempty"`
	// System Type Descriptor is only used (ie is not nil) when SystemIdentifier == 0
	SystemDescriptor *SystemTypeDescriptor `json:"system_type_descriptor,omitempty"`
	TypeIdLen        uint32                `json:"type_id_length"`
	UnitIdLen        uint32                `json:"unit_id_length"`
	Shards           ShardingScheme        `json:"sharding_scheme"`
	SummaryTrustBase []byte                `json:"summary_trust_base,omitempty"`
	T2Timeout        time.Duration         `json:"t2timeout"`
	FeeCreditBill    *FeeCreditBill        `json:"fee_credit_bill,omitempty"`
	//todo: Transaction cost function
}

type FeeCreditBill struct {
	_              struct{}       `cbor:",toarray"`
	UnitID         UnitID         `json:"unit_id,omitempty"`
	OwnerPredicate PredicateBytes `json:"owner_predicate,omitempty"`
}

func (pdr *PartitionDescriptionRecord) IsValid() error {
	if pdr == nil {
		return ErrSystemDescriptionIsNil
	}

	// we currently do not support custom System Type Descriptors so allow
	// only non-zero System IDs
	if pdr.SystemIdentifier == 0 {
		return fmt.Errorf("invalid system identifier: %s", pdr.SystemIdentifier)
	}
	if pdr.SystemDescriptor != nil {
		return errors.New("custom SystemDescriptor is not supported")
	}
	if n := len(pdr.Shards); n > 0 {
		return fmt.Errorf("currently only single shard partitions are supported, got sharding scheme with %d shards", n)
	}
	if pdr.TypeIdLen > 32 {
		return fmt.Errorf("type id length can be up to 32 bits, got %d", pdr.TypeIdLen)
	}
	if 64 > pdr.UnitIdLen || pdr.UnitIdLen > 512 {
		return fmt.Errorf("unit id length must be 64..512 bits, got %d", pdr.UnitIdLen)
	}
	if pdr.T2Timeout < 800*time.Millisecond || pdr.T2Timeout > 10*time.Second {
		return fmt.Errorf("t2 timeout value out of allowed range: %s", pdr.T2Timeout)
	}

	return nil
}

func (pdr *PartitionDescriptionRecord) AddToHasher(h hash.Hash) {
	buf := pdr.SystemIdentifier.Bytes() // SID.Bytes creates new slice on every call!
	buf = binary.BigEndian.AppendUint32(buf, pdr.TypeIdLen)
	buf = binary.BigEndian.AppendUint32(buf, pdr.UnitIdLen)
	buf = binary.BigEndian.AppendUint64(buf, uint64(pdr.T2Timeout.Nanoseconds()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(pdr.SummaryTrustBase)))
	h.Write(buf)

	h.Write(pdr.SummaryTrustBase)
	pdr.Shards.AddToHasher(h)
	pdr.SystemDescriptor.AddToHasher(h)
}

func (pdr *PartitionDescriptionRecord) Hash(hashAlgorithm crypto.Hash) []byte {
	hasher := hashAlgorithm.New()
	pdr.AddToHasher(hasher)
	return hasher.Sum(nil)
}

func (pdr *PartitionDescriptionRecord) GetSystemIdentifier() SystemID {
	return pdr.SystemIdentifier
}
