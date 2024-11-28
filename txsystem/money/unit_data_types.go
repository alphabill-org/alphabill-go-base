package money

import (
	"bytes"
	"fmt"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/txsystem/fc"
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var _ types.UnitData = (*BillData)(nil)

type BillData struct {
	_              struct{}  `cbor:",toarray"`
	Value          uint64    `json:"value,string"`   // The monetary value of this bill
	OwnerPredicate hex.Bytes `json:"ownerPredicate"` // The owner predicate of this bill
	Locked         uint64    `json:"locked,string"`  // The lock status of this bill (non-zero value means locked)
	Counter        uint64    `json:"counter,string"` // The transaction counter of this bill
}

func NewUnitData(unitID types.UnitID) (types.UnitData, error) {
	if unitID.HasType(BillUnitType) {
		return &BillData{}, nil
	}
	if unitID.HasType(FeeCreditRecordUnitType) {
		return &fc.FeeCreditRecord{}, nil
	}
	return nil, fmt.Errorf("unknown unit type in UnitID %s", unitID)
}

func NewBillData(value uint64, ownerPredicate []byte) *BillData {
	return &BillData{
		Value:          value,
		OwnerPredicate: ownerPredicate,
	}
}

func (b *BillData) Write(hasher abhash.Hasher) {
	hasher.Write(b)
}

func (b *BillData) SummaryValueInput() uint64 {
	return b.Value
}

func (b *BillData) Copy() types.UnitData {
	return &BillData{
		Value:          b.Value,
		OwnerPredicate: bytes.Clone(b.OwnerPredicate),
		Locked:         b.Locked,
		Counter:        b.Counter,
	}
}

func (b *BillData) IsLocked() bool {
	return b.Locked != 0
}

func (b *BillData) Owner() []byte {
	return b.OwnerPredicate
}
