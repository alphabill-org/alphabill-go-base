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

func (t *TransactionRecord) TxStatus() TxStatus {
	if t == nil {
		return 0
	}
	return t.ServerMetadata.TxStatus()
}

func (t *TransactionRecord) IsSuccessful() bool {
	return t.TxStatus() == TxStatusSuccessful
}

func (t *TransactionRecord) UnitID() UnitID {
	return t.GetTransactionOrder().GetUnitID()
}

func (t *TransactionRecord) GetTransactionOrder() *TransactionOrder {
	if t == nil {
		return nil
	}
	return t.TransactionOrder
}

func (t *TransactionRecord) TargetUnits() []UnitID {
	if t == nil {
		return nil
	}
	return t.ServerMetadata.GetTargetUnits()
}

func (t *TransactionRecord) IsValid() error {
	if t == nil {
		return ErrTransactionRecordIsNil
	}
	if t.TransactionOrder == nil {
		return ErrTransactionOrderIsNil
	}
	if t.ServerMetadata == nil {
		return ErrServerMetadataIsNil
	}
	return nil
}

func (sm *ServerMetadata) GetActualFee() uint64 {
	if sm == nil {
		return 0
	}
	return sm.ActualFee
}

func (sm *ServerMetadata) TxStatus() TxStatus {
	if sm == nil {
		return 0
	}
	return sm.SuccessIndicator
}

func (sm *ServerMetadata) UnmarshalDetails(v any) error {
	if sm == nil {
		return errors.New("server metadata is nil")
	}
	return Cbor.Unmarshal(sm.ProcessingDetails, v)
}

func (sm *ServerMetadata) SetError(e error) {
	if sm == nil {
		return
	}
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
	if sm == nil {
		return nil
	}
	return sm.errDetail
}

func (sm *ServerMetadata) GetTargetUnits() []UnitID {
	if sm == nil {
		return nil
	}
	return sm.TargetUnits
}

func (t *TxRecordProof) IsValid() error {
	if t == nil {
		return errors.New("transaction record proof is nil")
	}
	if err := t.TxRecord.IsValid(); err != nil {
		return err
	}
	if err := t.TxProof.IsValid(); err != nil {
		return err
	}
	return nil
}

func (t *TxRecordProof) UnitID() UnitID {
	return t.TransactionOrder().GetUnitID()
}

func (t *TxRecordProof) TransactionOrder() *TransactionOrder {
	if t == nil {
		return nil
	}
	return t.TxRecord.GetTransactionOrder()
}

func (t *TxRecordProof) ActualFee() uint64 {
	if t == nil {
		return 0
	}
	return t.TxRecord.GetActualFee()
}

func (t *TxRecordProof) TxStatus() TxStatus {
	if t == nil {
		return 0
	}
	return t.TxRecord.TxStatus()
}

func (t *TxRecordProof) Timeout() uint64 {
	return t.TransactionOrder().Timeout()
}

func (t *TxRecordProof) FeeCreditRecordID() []byte {
	return t.TransactionOrder().FeeCreditRecordID()
}

func (t *TxRecordProof) MaxFee() uint64 {
	return t.TransactionOrder().MaxFee()
}

func (t *TxRecordProof) ReferenceNumber() []byte {
	return t.TransactionOrder().ReferenceNumber()
}
