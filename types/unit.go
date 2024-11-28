package types

import (
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
)

type (
	// UnitData is a generic data type for the unit state.
	UnitData interface {
		Write(hasher abhash.Hasher)
		SummaryValueInput() uint64
		Copy() UnitData
		Owner() []byte
	}
)
