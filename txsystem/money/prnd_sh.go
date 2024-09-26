package money

import (
	"crypto"

	"github.com/alphabill-org/alphabill-go-base/types"
)

// billHashData defines the cbor data for calculating new bill ID.
type billHashData struct {
	_              struct{} `cbor:",toarray"`
	UnitID         types.UnitID
	Attributes     types.RawCBOR
	ClientMetadata *types.ClientMetadata
	SplitIndex     uint32
}

// HashForNewBillID generates a new bill ID (unit part of the extended identifier) from the transaction order.
// Use NewBillID to generate the extended identifier from the unit part.
func HashForNewBillID(tx *types.TransactionOrder, splitIndex uint32, hashAlgorithm crypto.Hash) ([]byte, error) {
	if tx == nil {
		return nil, types.ErrTransactionOrderIsNil
	}
	hashData := billHashData{
		UnitID:         tx.UnitID,
		Attributes:     tx.Attributes,
		ClientMetadata: tx.ClientMetadata,
		SplitIndex:     splitIndex,
	}
	return types.HashCBOR(hashData, hashAlgorithm)
}
