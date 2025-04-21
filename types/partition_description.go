package types

import (
	"crypto"
	"errors"
	"fmt"
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
	_           struct{}    `cbor:",toarray"`
	Version     ABVersion   `json:"version"`
	NetworkID   NetworkID   `json:"networkId"`
	PartitionID PartitionID `json:"partitionId"`
	ShardID     ShardID     `json:"shardId"`

	PartitionTypeID PartitionTypeID `json:"partitionTypeId"`
	PartitionType   *PartitionType  `json:"partitionType,omitempty"` // non-nil only if PartitionTypeID == 0
	TypeIDLen       uint32          `json:"typeIdLength"`
	UnitIDLen       uint32          `json:"unitIdLength"`

	SummaryTrustBase hex.Bytes      `json:"summaryTrustBase"`
	T2Timeout        time.Duration  `json:"t2timeout"`
	FeeCreditBill    *FeeCreditBill `json:"feeCreditBill"`
	//todo: Transaction cost function
	PartitionParams map[string]string `json:"partitionParams,omitempty"`

	Epoch      uint64      `json:"epoch"`
	EpochStart uint64      `json:"epochStart"` // Root round when this epoch is activated
	Validators []*NodeInfo `json:"validators"`
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
	if pdr.PartitionID == 0 {
		return fmt.Errorf("invalid partition identifier: %s", pdr.PartitionID)
	}
	// we currently do not support custom partition types, so allow
	// only non-zero PartitionTypeIDs
	if pdr.PartitionTypeID == 0 {
		return fmt.Errorf("invalid partition type identifier: %d", pdr.PartitionTypeID)
	}
	if pdr.PartitionType != nil {
		return errors.New("custom PartitionType is not supported")
	}
	if uint(pdr.UnitIDLen) <= pdr.ShardID.Length() {
		return fmt.Errorf("shard id length %d must be shorter than unit id length %d", pdr.ShardID.Length(), pdr.UnitIDLen)
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

	var validatorIDs = make(map[string]struct{})
	for i, v := range pdr.Validators {
		if err := v.IsValid(); err != nil {
			return fmt.Errorf("invalid validator at idx %d: %w", i, err)
		}
		if _, f := validatorIDs[v.NodeID]; f {
			return fmt.Errorf("duplicate validator with node id %q", v.NodeID)
		}
		validatorIDs[v.NodeID] = struct{}{}
	}

	return nil
}

// Verify verifies validator info and that it extends the previous shard conf if provided.
func (pdr *PartitionDescriptionRecord) Verify(prev *PartitionDescriptionRecord) error {
	if prev != nil {
		if pdr.NetworkID != prev.NetworkID {
			return fmt.Errorf("invalid network id, provided %d previous %d", pdr.NetworkID, prev.NetworkID)
		}
		if pdr.PartitionID != prev.PartitionID {
			return fmt.Errorf("invalid partition id, provided %d previous %d", pdr.PartitionID, prev.PartitionID)
		}
		if !pdr.ShardID.Equal(prev.ShardID) {
			return fmt.Errorf("invalid shard id, provided \"0x%x\" previous \"0x%x\"", pdr.ShardID.Bytes(), prev.ShardID.Bytes())
		}
		if pdr.Epoch != prev.Epoch+1 {
			return fmt.Errorf("invalid epoch, provided %d previous %d", pdr.Epoch, prev.Epoch)
		}
		if pdr.EpochStart <= prev.EpochStart {
			return fmt.Errorf("invalid epoch start, provided %d previous %d", pdr.EpochStart, prev.EpochStart)
		}
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
