package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	NetworkMainNet NetworkID = 1
	NetworkTestNet NetworkID = 2
	NetworkLocal   NetworkID = 3
)

const (
	SystemIdentifierLength  = 4
	NetworkIdentifierLength = 2
)

type (
	NetworkID uint16
	SystemID  uint32

	// UnitID is the extended identifier, combining the type and the unit identifiers.
	UnitID []byte
)

// NewUnitID creates a new UnitID consisting of a shardPart, unitPart and typePart.
func NewUnitID(unitIDLength int, shardPart []byte, unitPart []byte, typePart []byte) UnitID {
	unitID := make([]byte, unitIDLength)

	// The number of bytes to reserve for typePart in the new UnitID.
	typePartLength := len(typePart)
	// The number of bytes to reserve for unitPart in the new UnitID.
	unitPartLength := unitIDLength - typePartLength
	// The number of bytes to overwrite in the unitPart of the new UnitID with the shardPart.
	shardPartLength := 0

	// Copy unitPart, leaving zero bytes in the beginning in case
	// unitPart is shorter than unitPartLength.
	unitPartStart := max(0, unitPartLength-len(unitPart))
	copy(unitID[unitPartStart:], unitPart)

	// Copy typePart
	copy(unitID[unitPartLength:], typePart)

	// Copy shardPart, overwriting shardPartLength bytes at the beginning of unitPart.
	copy(unitID, shardPart[:shardPartLength])

	return unitID
}

func (uid UnitID) Compare(key UnitID) int {
	return bytes.Compare(uid, key)
}

func (uid UnitID) String() string {
	return fmt.Sprintf("%X", []byte(uid))
}

func (uid UnitID) Eq(id UnitID) bool {
	return bytes.Equal(uid, id)
}

func (uid UnitID) HasType(typePart []byte) bool {
	return bytes.HasSuffix(uid, typePart)
}

func (uid UnitID) MarshalText() ([]byte, error) {
	return toHex(uid), nil
}

func (uid *UnitID) UnmarshalText(src []byte) error {
	res, err := fromHex(src)
	if err == nil {
		*uid = res
	}
	return err
}

func BytesToSystemID(b []byte) (SystemID, error) {
	if len(b) != SystemIdentifierLength {
		return 0, fmt.Errorf("partition ID length must be %d bytes, got %d bytes", SystemIdentifierLength, len(b))
	}

	return SystemID(binary.BigEndian.Uint32(b)), nil
}

func (sid SystemID) Bytes() []byte {
	b := make([]byte, SystemIdentifierLength)
	binary.BigEndian.PutUint32(b, uint32(sid))
	return b
}

func (sid SystemID) String() string {
	return fmt.Sprintf("%08X", uint32(sid))
}

func (nid NetworkID) Bytes() []byte {
	b := make([]byte, NetworkIdentifierLength)
	binary.BigEndian.PutUint16(b, uint16(nid))
	return b
}
