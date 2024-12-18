package orchestration

import (
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/types"
)

const (
	VarUnitType = 1
)

func NewUnitData(unitID types.UnitID, pdr *types.PartitionDescriptionRecord) (types.UnitData, error) {
	typeID, err := pdr.ExtractUnitType(unitID)
	if err != nil {
		return nil, fmt.Errorf("extracting type ID: %w", err)
	}

	if typeID == VarUnitType {
		return &VarData{}, nil
	}

	return nil, fmt.Errorf("unknown unit type in UnitID %s", unitID)
}
