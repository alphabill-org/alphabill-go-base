package types

import (
	"crypto"
	"errors"
)

var ErrOutOfGas = errors.New("out of gas")

const (
	// TxStatusFailed is the status code of a transaction if execution failed.
	TxStatusFailed TxStatus = 0
	// TxStatusSuccessful is the status code of a transaction if execution succeeded.
	TxStatusSuccessful TxStatus = 1
	// TxErrOutOfGas tx execution run out of gas, try with bigger 'MaxTransactionFee'
	TxErrOutOfGas TxStatus = 2
)

type (
	TxStatus uint64

	// TransactionRecord is a transaction order with "server-side" metadata added to it. TransactionRecord is a structure
	// that is added to the block.
	TransactionRecord struct {
		_                struct{} `cbor:",toarray"`
		TransactionOrder *TransactionOrder
		ServerMetadata   *ServerMetadata
	}

	ServerMetadata struct {
		_                 struct{} `cbor:",toarray"`
		ActualFee         uint64
		TargetUnits       []UnitID
		SuccessIndicator  TxStatus
		ProcessingDetails RawCBOR
		errDetail         error
	}

	TxRecordProof struct {
		_        struct{} `cbor:",toarray"`
		TxRecord *TransactionRecord
		TxProof  *TxProof
	}
)

func (t *TransactionRecord) Hash(algorithm crypto.Hash) []byte {
	bytes, err := t.Bytes()
	if err != nil {
		// TODO
		panic(err)
	}
	hasher := algorithm.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}

func (t *TransactionRecord) Bytes() ([]byte, error) {
	return Cbor.Marshal(t)
}

func (t *TransactionRecord) UnmarshalProcessingDetails(v any) error {
	if t == nil {
		return errors.New("transaction record is nil")
	}
	return t.ServerMetadata.UnmarshalDetails(v)
}

func (t *TransactionRecord) GetActualFee() uint64 {
	if t == nil {
		return 0
	}
	return t.ServerMetadata.GetActualFee()
}

func (t *TransactionRecord) IsSuccessful() bool {
	if t == nil || t.ServerMetadata == nil {
		return false
	}
	return t.ServerMetadata.SuccessIndicator == TxStatusSuccessful
}

func (sm *ServerMetadata) GetActualFee() uint64 {
	if sm == nil {
		return 0
	}
	return sm.ActualFee
}

func (sm *ServerMetadata) UnmarshalDetails(v any) error {
	if sm == nil {
		return errors.New("server metadata is nil")
	}
	return Cbor.Unmarshal(sm.ProcessingDetails, v)
}

func (sm *ServerMetadata) SetError(e error) {
	// on error clear changed units
	if errors.Is(e, ErrOutOfGas) {
		sm.SuccessIndicator = TxErrOutOfGas
	} else {
		sm.SuccessIndicator = TxStatusFailed
	}
	sm.TargetUnits = []UnitID{}
	sm.errDetail = e
}

func (sm *ServerMetadata) ErrDetail() error {
	return sm.errDetail
}
