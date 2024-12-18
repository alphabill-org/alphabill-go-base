package money

import (
	"crypto"
	"fmt"

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

/*
PrndSh returns function which generates pseudo-random byte sequence based on the transaction order.
Meant to be used as unit identifier generator. Can be called multiple times, each subsequent call
will return different byte sequence (to generate unit IDs for bill splitting)
*/
func PrndSh(txo *types.TransactionOrder) func(buf []byte) error {
	hashData := billHashData{
		UnitID:         txo.UnitID,
		Attributes:     txo.Attributes,
		ClientMetadata: txo.ClientMetadata,
		SplitIndex:     0,
	}

	return func(buf []byte) error {
		h, err := types.HashCBOR(hashData, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("hashing txo data: %w", err)
		}
		if n := copy(buf, h); n != len(buf) {
			return fmt.Errorf("requested %d bytes but got %d", len(buf), n)
		}
		hashData.SplitIndex++
		return nil
	}
}
