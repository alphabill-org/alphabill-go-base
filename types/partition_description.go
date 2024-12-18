package types

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"time"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var (
	ErrSystemDescriptionIsNil = errors.New("system description record is nil")
)

type PartitionType struct {
	// This is just a placeholder right now so that we can add
	// the field into the PartitionDescriptionRecord - for the fast track
	// solution we do not expect to have non nil PartitionType
	// so the actual field list is not needed...
}

func (std *PartitionType) AddToHasher(h abhash.Hasher) {
	h.Write(std)
}

type PartitionDescriptionRecord struct {
	_                struct{}        `cbor:",toarray"`
	Version          ABVersion       `json:"version"`
	NetworkID        NetworkID       `json:"networkId"`
	PartitionID      PartitionID     `json:"partitionId"`
	PartitionTypeID  PartitionTypeID `json:"partitionTypeId"`
	PartitionType    *PartitionType  `json:"partitionType,omitempty"` // non-nil only if PartitionTypeID == 0
	TypeIDLen        uint32          `json:"typeIdLength"`
	UnitIDLen        uint32          `json:"unitIdLength"`
	Shards           ShardingScheme  `json:"shardingScheme"`
	SummaryTrustBase hex.Bytes       `json:"summaryTrustBase"`
	T2Timeout        time.Duration   `json:"t2timeout"`
	FeeCreditBill    *FeeCreditBill  `json:"feeCreditBill"`
	//todo: Transaction cost function
}

type FeeCreditBill struct {
	_              struct{}       `cbor:",toarray"`
	UnitID         UnitID         `json:"unitId"`
	OwnerPredicate PredicateBytes `json:"ownerPredicate"`
}

func (pdr *PartitionDescriptionRecord) IsValid() error {
	if pdr == nil {
		return ErrSystemDescriptionIsNil
	}
	if pdr.Version != 1 {
		return ErrInvalidVersion(pdr)
	}
	if pdr.NetworkID == 0 {
		return fmt.Errorf("invalid network identifier: %d", pdr.NetworkID)
	}
	// we currently do not support custom System Type Descriptors so allow
	// only non-zero System IDs
	if pdr.PartitionID == 0 {
		return fmt.Errorf("invalid partition identifier: %s", pdr.PartitionID)
	}
	if pdr.PartitionType != nil {
		return errors.New("custom SystemDescriptor is not supported")
	}
	if n := len(pdr.Shards); n > 0 {
		return fmt.Errorf("currently only single shard partitions are supported, got sharding scheme with %d shards", n)
	}

	if pdr.TypeIDLen > 32 {
		return fmt.Errorf("type id length can be up to 32 bits, got %d", pdr.TypeIDLen)
	}
	if pdr.TypeIDLen%8 != 0 {
		return fmt.Errorf("type id length must be in full bytes, got %d bytes and %d bits", pdr.TypeIDLen/8, pdr.TypeIDLen%8)
	}

	if 64 > pdr.UnitIDLen || pdr.UnitIDLen > 512 {
		return fmt.Errorf("unit id length must be 64..512 bits, got %d", pdr.UnitIDLen)
	}
	if pdr.UnitIDLen%8 != 0 {
		return fmt.Errorf("unit id length must be in full bytes, got %d bytes and %d bits", pdr.UnitIDLen/8, pdr.UnitIDLen%8)
	}

	if pdr.T2Timeout < 800*time.Millisecond || pdr.T2Timeout > 10*time.Second {
		return fmt.Errorf("t2 timeout value out of allowed range: %s", pdr.T2Timeout)
	}

	return nil
}

func (pdr *PartitionDescriptionRecord) Hash(hashAlgorithm crypto.Hash) ([]byte, error) {
	hasher := abhash.New(hashAlgorithm.New())
	hasher.Write(pdr)
	return hasher.Sum()
}

func (pdr *PartitionDescriptionRecord) GetNetworkID() NetworkID {
	return pdr.NetworkID
}

func (pdr *PartitionDescriptionRecord) GetPartitionID() PartitionID {
	return pdr.PartitionID
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
	if pdr.UnitIDLen < uint32(id.Length()) {
		return fmt.Errorf("partition has %d bit unit IDs but shard ID is %d bits", pdr.UnitIDLen, id.Length())
	}
	if id.Length() != 0 && !slices.ContainsFunc(pdr.Shards, func(x ShardID) bool { return id.Equal(x) }) {
		return fmt.Errorf("shard ID %s doesn't belong into the sharding scheme", id)
	}
	return nil
}

/*
UnitIDValidator returns function which checks that unit ID passed as argument
has correct length and that the unit belongs into the given shard.
*/
func (pdr *PartitionDescriptionRecord) UnitIDValidator(sid ShardID) func(unitID UnitID) error {
	shardMatcher := sid.Comparator()
	idLen := int(pdr.TypeIDLen+pdr.UnitIDLen) / 8
	if (pdr.TypeIDLen+pdr.UnitIDLen)%8 > 0 {
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

func (pdr *PartitionDescriptionRecord) ComposeUnitID(shard ShardID, unitType uint32, prndSh func([]byte) error) (UnitID, error) {
	mask := uint32(1<<pdr.TypeIDLen) - 1
	if unitType > mask {
		return nil, fmt.Errorf("provided unit type ID %#x uses more than max allowed %d bits", unitType, pdr.TypeIDLen)
	}

	buf := make([]byte, (pdr.UnitIDLen+pdr.TypeIDLen)/8)

	// generate UnitIDLen bytes of random into the buf
	if err := prndSh(buf[:int(pdr.UnitIDLen)/8]); err != nil {
		return nil, fmt.Errorf("generating unit ID: %w", err)
	}

	// replace shard part
	idx, bits := shard.length/8, shard.length%8
	copy(buf, shard.bits[:idx])
	if bits != 0 {
		mask := byte(0xFF << (8 - bits))
		buf[idx] = (buf[idx] &^ mask) | shard.bits[idx]
	}

	// set type part
	for idx := len(buf) - 1; mask > 0; idx-- {
		buf[idx] = byte(unitType)
		unitType >>= 8
		mask >>= 8
	}

	return buf, nil
}

func (pdr *PartitionDescriptionRecord) ExtractUnitType(id UnitID) (uint32, error) {
	if pdr.TypeIDLen > 32 {
		return 0, fmt.Errorf("partition uses %d bit type identifiers", pdr.TypeIDLen)
	}

	if idLen := int(pdr.TypeIDLen+pdr.UnitIDLen) / 8; len(id) != idLen {
		return 0, fmt.Errorf("expected unit ID length %d bytes, got %d bytes", idLen, len(id))
	}

	// we relay on the fact that valid PDR has "pdr.UnitIDLen >= 64" ie it's safe to read four bytes
	idx := len(id) - 1
	v := uint32(id[idx]) | (uint32(id[idx-1]) << 8) | (uint32(id[idx-2]) << 16) | (uint32(id[idx-3]) << 24)
	mask := uint32(0xFFFFFFFF) >> (32 - pdr.TypeIDLen)
	return v & mask, nil
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
	if err := Cbor.UnmarshalTaggedValue(PartitionDescriptionRecordTag, data, (*alias)(pdr)); err != nil {
		return fmt.Errorf("failed to unmarshal partition description record: %w", err)
	}
	return EnsureVersion(pdr, pdr.Version, 1)
}
