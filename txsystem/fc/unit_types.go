package fc

import (
	"crypto"

	"github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
)

func NewFeeCreditRecordUnitPart(ownerPredicate []byte, timeout uint64) (types.UnitID, error) {
	return hash.HashValues(crypto.SHA256, ownerPredicate, timeout)
}
