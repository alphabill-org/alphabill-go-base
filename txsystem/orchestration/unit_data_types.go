package orchestration

import (
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
)

var _ types.UnitData = (*VarData)(nil)

// VarData Validator Assignment Record Data
type VarData struct {
	_           struct{} `cbor:",toarray"`
	EpochNumber uint64   // epoch number from the validator assignment record
}

func (b *VarData) Write(hasher abhash.Hasher) {
	hasher.Write(b)
}

func (b *VarData) SummaryValueInput() uint64 {
	return 0 // no summary value checks in orchestration partition
}

func (b *VarData) Copy() types.UnitData {
	return &VarData{
		EpochNumber: b.EpochNumber,
	}
}

func (b *VarData) Owner() []byte {
	return nil
}
