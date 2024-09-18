package interface_uc_array_cbor_tags

import (
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
)

type TransactionOrderV1 struct {
	_      struct{} `cbor:",toarray"`
	TypeID uint8
}

func (to *TransactionOrderV1) GetVersion() ABTag {
	return TXO1Tag
}

func (to *TransactionOrderV1) GetTypeID() uint8 {
	return to.TypeID
}

func (to *TransactionOrderV1) MarshalCBOR() ([]byte, error) {
	type alias TransactionOrderV1
	return types.Cbor.Marshal(cbor.Tag{
		Number:  uint64(TXO1Tag),
		Content: (*alias)(to),
	})
}

func (to *TransactionOrderV1) UnmarshalCBOR(data []byte) error {
	type alias TransactionOrderV1
	var aux = (*alias)(to)
	return types.Cbor.Unmarshal(data, aux)
}
