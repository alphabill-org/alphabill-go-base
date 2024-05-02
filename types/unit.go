package types

import (
	"hash"
)

type (
	// UnitData is a generic data type for the unit state.
	UnitData interface {
		Write(hasher hash.Hash) error
		SummaryValueInput() uint64
		Copy() UnitData
		IncrementCounter()
	}
)
