package fc

import (
	"crypto"

	"github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill-go-base/util"
)

func NewFeeCreditRecordUnitPart(ownerPredicate []byte, timeout uint64) types.UnitID {
	return hash.Sum(crypto.SHA256, ownerPredicate, util.Uint64ToBytes(timeout))
}
