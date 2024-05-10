package fc

import (
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/types"
)

var _ types.UnitData = (*FeeCreditRecord)(nil)

// FeeCreditRecord state tree unit data of fee credit records.
// Holds fee credit balance for individual users,
// not to be confused with fee credit bills which contain aggregate fees for a given partition.
type FeeCreditRecord struct {
	_       struct{} `cbor:",toarray"`
	Balance uint64   `json:"balance,string"` // current balance
	Counter uint64   `json:"counter,string"` // transaction counter; incremented with reach “addFC”, "closeFC", "lockFC" or "unlockFC" transaction; spending fee credit does not change this value
	Timeout uint64   `json:"timeout,string"` // the earliest round number when this record may be “garbage collected” if the balance goes to zero
	Locked  uint64   `json:"locked,string"`  // lock status of the fee credit record, non-zero value means locked; locked free credit does not prevent spending the fee credit
}

func (b *FeeCreditRecord) Write(hasher hash.Hash) error {
	res, err := types.Cbor.Marshal(b)
	if err != nil {
		return fmt.Errorf("fee credit serialization error: %w", err)
	}
	_, err = hasher.Write(res)
	return err
}

func (b *FeeCreditRecord) SummaryValueInput() uint64 {
	return 0
}

func (b *FeeCreditRecord) Copy() types.UnitData {
	return &FeeCreditRecord{
		Balance: b.Balance,
		Counter: b.Counter,
		Timeout: b.Timeout,
		Locked:  b.Locked,
	}
}

func (b *FeeCreditRecord) GetCounter() uint64 {
	if b == nil {
		return 0
	}
	return b.Counter
}

func (b *FeeCreditRecord) IsLocked() bool {
	return b.Locked != 0
}
