package types

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

const (
	NetworkMainNet NetworkID = 1
	NetworkTestNet NetworkID = 2
	NetworkLocal   NetworkID = 3
)

const (
	PartitionIDLength = 4
	NetworkIDLength   = 2
)

type (
	NetworkID       uint16
	PartitionID     uint32
	PartitionTypeID uint32

	PartitionShardID struct {
		_           struct{} `cbor:",toarray"`
		PartitionID PartitionID
		ShardID     string // types.ShardID is not comparable
	}

	// UnitID is the extended identifier, combining the type and the unit identifiers.
	UnitID []byte
)

func (uid UnitID) Compare(key UnitID) int {
	return bytes.Compare(uid, key)
}

func (uid UnitID) String() string {
	return fmt.Sprintf("%X", []byte(uid))
}

func (uid UnitID) Eq(id UnitID) bool {
	return bytes.Equal(uid, id)
}

func (uid UnitID) TypeMustBe(typeID uint32, pdr *PartitionDescriptionRecord) error {
	tid, err := pdr.ExtractUnitType(uid)
	if err != nil {
		return fmt.Errorf("extracting unit type from unit ID: %w", err)
	}
	if tid != typeID {
		return fmt.Errorf("expected type %#X, got %#X", typeID, tid)
	}
	return nil
}

func (uid UnitID) MarshalText() ([]byte, error) {
	return hex.Encode(uid), nil
}

func (uid *UnitID) UnmarshalText(src []byte) error {
	res, err := hex.Decode(src)
	if err == nil {
		*uid = res
	}
	return err
}

func BytesToPartitionID(b []byte) (PartitionID, error) {
	if len(b) != PartitionIDLength {
		return 0, fmt.Errorf("partition ID length must be %d bytes, got %d bytes", PartitionIDLength, len(b))
	}

	return PartitionID(binary.BigEndian.Uint32(b)), nil
}

func (sid PartitionID) Bytes() []byte {
	b := make([]byte, PartitionIDLength)
	binary.BigEndian.PutUint32(b, uint32(sid))
	return b
}

func (sid PartitionID) String() string {
	return fmt.Sprintf("%08X", uint32(sid))
}

func (nid NetworkID) Bytes() []byte {
	b := make([]byte, NetworkIDLength)
	binary.BigEndian.PutUint16(b, uint16(nid))
	return b
}

func (i *PartitionShardID) String() string {
	return fmt.Sprintf("%s_%x", i.PartitionID, i.ShardID)
}
