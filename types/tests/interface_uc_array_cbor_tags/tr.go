package interface_uc_array_cbor_tags

import (
	"github.com/alphabill-org/alphabill-go-base/types"
)

type TransactionRecord struct {
	_  struct{} `cbor:",toarray"`
	Tx TransactionOrder
}

func (tr *TransactionRecord) MarshalCBOR() ([]byte, error) {
	type alias TransactionRecord
	txBytes, err := types.Cbor.Marshal(tr.Tx)
	if err != nil {
		return nil, err
	}
	return types.Cbor.Marshal(&struct {
		_ struct{} `cbor:",toarray"`
		*alias
		Tx []byte
	}{
		alias: (*alias)(tr),
		Tx:    txBytes,
	})
}

func (tr *TransactionRecord) UnmarshalCBOR(data []byte) error {
	type alias TransactionRecord
	aux := &struct {
		_ struct{} `cbor:",toarray"`
		*alias
		Tx []byte
	}{
		alias: (*alias)(tr),
	}
	if err := types.Cbor.Unmarshal(data, aux); err != nil {
		return err
	}
	txo, err := decodeTransactionOrder(aux.Tx)
	if err != nil {
		return err
	}
	tr.Tx = txo
	return nil
}
