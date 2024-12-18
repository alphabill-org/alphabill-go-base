package tokens

import (
	"crypto"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/types"
)

// tokenHashData defines the cbor data for calculating new token ID.
type tokenHashData struct {
	_              struct{} `cbor:",toarray"`
	Attributes     types.RawCBOR
	ClientMetadata *types.ClientMetadata
}

/*
PrndSh returns function which generates pseudo-random byte sequence based on the transaction order.
Meant to be used as unit identifier generator in PDR.ComposeUnitID.
Subsequent calls return the same value.
*/
func PrndSh(txo *types.TransactionOrder) func(buf []byte) error {
	return func(buf []byte) error {
		if txo == nil {
			return types.ErrTransactionOrderIsNil
		}
		hashData := tokenHashData{
			Attributes:     txo.Attributes,
			ClientMetadata: txo.ClientMetadata,
		}

		h, err := types.HashCBOR(hashData, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("hashing txo data: %w", err)
		}
		if n := copy(buf, h); n != len(buf) {
			return fmt.Errorf("requested %d bytes but got %d", len(buf), n)
		}
		return nil
	}
}
