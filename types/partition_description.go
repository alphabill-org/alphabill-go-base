package types

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"slices"
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
	_                 struct{}  `cbor:",toarray"`
	Version           ABVersion `json:"version,omitempty"`
	NetworkIdentifier NetworkID `json:"network_identifier,omitempty"`
	SystemIdentifier  SystemID  `json:"system_identifier,omitempty"`
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
	if pdr.Version == 0 {
		return ErrInvalidVersion(pdr)
	}
	if pdr.NetworkIdentifier == 0 {
		return fmt.Errorf("invalid network identifier: %d", pdr.NetworkIdentifier)
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
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, pdr.Version)
	buf = binary.BigEndian.AppendUint16(buf, uint16(pdr.NetworkIdentifier))
	buf = binary.BigEndian.AppendUint32(buf, uint32(pdr.SystemIdentifier))
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

func (pdr *PartitionDescriptionRecord) GetNetworkIdentifier() NetworkID {
	return pdr.NetworkIdentifier
}

func (pdr *PartitionDescriptionRecord) GetSystemIdentifier() SystemID {
	return pdr.SystemIdentifier
}

/*
IsValidShard checks if the argument is a valid shard ID in the Partition.
*/
func (pdr *PartitionDescriptionRecord) IsValidShard(id ShardID) error {
	if len(pdr.Shards) == 0 && id.Length() != 0 {
		return errors.New("only empty shard ID is valid in a single-shard sharding scheme")
	}
	if len(pdr.Shards) != 0 && id.Length() == 0 {
		return errors.New("empty shard ID is not valid in multi-shard sharding scheme")
	}
	if pdr.UnitIdLen < uint32(id.Length()) {
		return fmt.Errorf("partition has %d bit unit IDs but shard ID is %d bits", pdr.UnitIdLen, id.Length())
	}
	if id.Length() != 0 && !slices.ContainsFunc(pdr.Shards, func(x ShardID) bool { return id.Equal(x) }) {
		return fmt.Errorf("shard ID %s doesn't belong into the sharding scheme", id)
	}
	return nil
}

/*
UnitIdValidator returns function which checks that unit ID passed as argument
has correct length and that the unit belongs into the given shard.
*/
func (pdr *PartitionDescriptionRecord) UnitIdValidator(sid ShardID) func(unitID UnitID) error {
	shardMatcher := sid.Comparator()
	idLen := int(pdr.TypeIdLen+pdr.UnitIdLen) / 8
	if (pdr.TypeIdLen+pdr.UnitIdLen)%8 > 0 {
		idLen++
	}

	return func(unitID UnitID) error {
		if len(unitID) != idLen {
			return fmt.Errorf("expected %d byte unit ID, got %d bytes", idLen, len(unitID))
		}
		if !shardMatcher(unitID) {
			return errors.New("unit doesn't belong into the shard")
		}
		return nil
	}
}

func (pdr *PartitionDescriptionRecord) GetVersion() ABVersion {
	if pdr == nil || pdr.Version == 0 {
		return 1
	}
	return pdr.Version
}

func (pdr *PartitionDescriptionRecord) MarshalCBOR() ([]byte, error) {
	type alias PartitionDescriptionRecord
	if pdr.Version == 0 {
		pdr.Version = pdr.GetVersion()
	}
	return Cbor.MarshalTaggedValue(PartitionDescriptionRecordTag, (*alias)(pdr))
}

func (pdr *PartitionDescriptionRecord) UnmarshalCBOR(data []byte) error {
	type alias PartitionDescriptionRecord
	if err := Cbor.Unmarshal(data, (*alias)(pdr)); err != nil {
		return err
	}
	return nil
}
