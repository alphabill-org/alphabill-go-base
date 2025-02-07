package orchestration

import (
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
)

var _ types.UnitData = (*VarData)(nil)

// VarData Validator Assignment Record Data
type VarData struct {
	_           struct{}        `cbor:",toarray"`
	Version     types.ABVersion `json:"version"`
	EpochNumber uint64          // epoch number from the validator assignment record
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

func (b *VarData) GetVersion() types.ABVersion {
	if b != nil && b.Version != 0 {
		return b.Version
	}
	return 1
}

func (b *VarData) MarshalCBOR() ([]byte, error) {
	type alias VarData
	if b.Version == 0 {
		b.Version = b.GetVersion()
	}
	return types.Cbor.MarshalTaggedValue(types.UnitDataTag, (*alias)(b))
}

func (b *VarData) UnmarshalCBOR(data []byte) error {
	type alias VarData
	if err := types.Cbor.UnmarshalTaggedValue(types.UnitDataTag, data, (*alias)(b)); err != nil {
		return err
	}
	return types.EnsureVersion(b, b.Version, 1)
}
