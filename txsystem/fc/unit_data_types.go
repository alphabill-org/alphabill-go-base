package fc

import (
	"bytes"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var _ types.UnitData = (*FeeCreditRecord)(nil)

// FeeCreditRecord state tree unit data of fee credit records.
// Holds fee credit balance for individual users,
// not to be confused with fee credit bills which contain aggregate fees for a given partition.
type FeeCreditRecord struct {
	_              struct{}        `cbor:",toarray"`
	Version        types.ABVersion `json:"version"`
	Balance        uint64          `json:"balance,string"`     // current balance
	OwnerPredicate hex.Bytes       `json:"ownerPredicate"`     // the owner predicate of this fee credit record
	Counter        uint64          `json:"counter,string"`     // transaction counter; incremented with each “addFC” or "closeFC" transaction; spending fee credit does not change this value
	MinLifetime    uint64          `json:"minLifetime,string"` // the earliest round number when this record may be deleted if the balance goes to zero
}

func NewFeeCreditRecord(balance uint64, ownerPredicate []byte, minLifetime uint64) *FeeCreditRecord {
	return &FeeCreditRecord{
		Balance:        balance,
		OwnerPredicate: ownerPredicate,
		MinLifetime:    minLifetime,
	}
}

func (b *FeeCreditRecord) Write(hasher abhash.Hasher) {
	hasher.Write(b)
}

func (b *FeeCreditRecord) SummaryValueInput() uint64 {
	return 0
}

func (b *FeeCreditRecord) Copy() types.UnitData {
	return &FeeCreditRecord{
		Balance:        b.Balance,
		OwnerPredicate: bytes.Clone(b.OwnerPredicate),
		Counter:        b.Counter,
		MinLifetime:    b.MinLifetime,
	}
}

func (b *FeeCreditRecord) GetCounter() uint64 {
	if b == nil {
		return 0
	}
	return b.Counter
}

func (b *FeeCreditRecord) Owner() []byte {
	return b.OwnerPredicate
}

func (b *FeeCreditRecord) GetVersion() types.ABVersion {
	if b != nil && b.Version != 0 {
		return b.Version
	}
	return 1
}

func (b *FeeCreditRecord) MarshalCBOR() ([]byte, error) {
	type alias FeeCreditRecord
	if b.Version == 0 {
		b.Version = b.GetVersion()
	}
	return cbor.Marshal((*alias)(b))
}

func (b *FeeCreditRecord) UnmarshalCBOR(data []byte) error {
	type alias FeeCreditRecord
	if err := cbor.Unmarshal(data, (*alias)(b)); err != nil {
		return err
	}
	return types.EnsureVersion(b, b.Version, 1)
}

func (b *FeeCreditRecord) IsExpired(currentRoundNumber uint64) bool {
	return b.Balance == 0 && b.MinLifetime < currentRoundNumber
}
