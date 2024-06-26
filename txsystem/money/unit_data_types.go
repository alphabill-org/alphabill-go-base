package money

import (
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/txsystem/fc"
	"github.com/alphabill-org/alphabill-go-base/types"
)

var _ types.UnitData = (*BillData)(nil)

type BillData struct {
	_       struct{} `cbor:",toarray"`
	V       uint64   `json:"value,string"`      // The monetary value of this bill
	T       uint64   `json:"lastUpdate,string"` // The round number of the last transaction with the bill
	Counter uint64   `json:"counter,string"`    // The transaction counter of this bill
	Locked  uint64   `json:"locked,string"`     // locked status of the bill, non-zero value means locked
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

func (b *BillData) Write(hasher hash.Hash) error {
	res, err := types.Cbor.Marshal(b)
	if err != nil {
		return fmt.Errorf("unit data encode error: %w", err)
	}
	_, err = hasher.Write(res)
	return err
}

func (b *BillData) SummaryValueInput() uint64 {
	return b.V
}

func (b *BillData) Copy() types.UnitData {
	return &BillData{
		V:       b.V,
		T:       b.T,
		Counter: b.Counter,
		Locked:  b.Locked,
	}
}

func (b *BillData) IsLocked() bool {
	return b.Locked != 0
}
