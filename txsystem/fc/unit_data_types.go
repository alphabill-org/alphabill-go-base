package fc

import (
	"bytes"
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/types"
)

var _ types.UnitData = (*FeeCreditRecord)(nil)

// FeeCreditRecord state tree unit data of fee credit records.
// Holds fee credit balance for individual users,
// not to be confused with fee credit bills which contain aggregate fees for a given partition.
type FeeCreditRecord struct {
	_              struct{} `cbor:",toarray"`
	Balance        uint64   `json:"balance,string"` // current balance
	OwnerPredicate []byte   `json:"ownerPredicate"` // the owner predicate of this fee credit record
	Locked         uint64   `json:"locked,string"`  // the lock status of the fee credit record (non-zero value means locked); locked free credit does not prevent spending the fee credit
	Counter        uint64   `json:"counter,string"` // transaction counter; incremented with each “addFC”, "closeFC", "lockFC" or "unlockFC" transaction; spending fee credit does not change this value
	Timeout        uint64   `json:"timeout,string"` // the earliest round number when this record may be deleted if the balance goes to zero
}

func NewFeeCreditRecord(balance uint64, ownerPredicate []byte, timeout uint64) *FeeCreditRecord {
	return &FeeCreditRecord{
		Balance:        balance,
		OwnerPredicate: ownerPredicate,
		Timeout:        timeout,
	}
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
		Balance:        b.Balance,
		OwnerPredicate: bytes.Clone(b.OwnerPredicate),
		Locked:         b.Locked,
		Counter:        b.Counter,
		Timeout:        b.Timeout,
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

func (b *FeeCreditRecord) Owner() []byte {
	return b.OwnerPredicate
}
