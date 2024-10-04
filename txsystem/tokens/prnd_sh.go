package tokens

import (
	"crypto"

	"github.com/alphabill-org/alphabill-go-base/types"
)

// tokenHashData defines the cbor data for calculating new token ID.
type tokenHashData struct {
	_              struct{} `cbor:",toarray"`
	Attributes     types.RawCBOR
	ClientMetadata *types.ClientMetadata
}

// HashForNewTokenID generates new token ID (unit part of the extended identifier) from the transaction order.
// Use NewFungibleTokenID or NewNonFungibleTokenID to generate the extended identifier from the unit part.
func HashForNewTokenID(tx *types.TransactionOrder, hashFunc crypto.Hash) ([]byte, error) {
	if tx == nil {
		return nil, types.ErrTransactionOrderIsNil
	}
	hashData := tokenHashData{
		Attributes:     tx.Attributes,
		ClientMetadata: tx.ClientMetadata,
	}
	return types.HashCBOR(hashData, hashFunc)
}
