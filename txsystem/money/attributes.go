package money

import (
	"github.com/alphabill-org/alphabill-go-base/types"
)

const DefaultSystemID types.SystemID = 1

const (
	TransactionTypeTransfer uint16 = 1
	TransactionTypeSplit    uint16 = 2
	TransactionTypeTransDC  uint16 = 3
	TransactionTypeSwapDC   uint16 = 4
	TransactionTypeLock     uint16 = 5
	TransactionTypeUnlock   uint16 = 6
)

type (
	TransferAttributes struct {
		_                 struct{} `cbor:",toarray"`
		TargetValue       uint64
		NewOwnerPredicate []byte
		Counter           uint64
	}

	TransferDCAttributes struct {
		_                 struct{} `cbor:",toarray"`
		Value             uint64
		TargetUnitID      []byte
		TargetUnitCounter uint64
		Counter           uint64
	}

	SplitAttributes struct {
		_           struct{} `cbor:",toarray"`
		TargetUnits []*TargetUnit
		Counter     uint64
	}

	SwapDCAttributes struct {
		_                  struct{}               `cbor:",toarray"`
		DustTransferProofs []*types.TxRecordProof // the dust transfer records and proofs
	}

	LockAttributes struct {
		_          struct{} `cbor:",toarray"`
		LockStatus uint64   // status of the lock, non-zero value means locked
		Counter    uint64
	}

	UnlockAttributes struct {
		_       struct{} `cbor:",toarray"`
		Counter uint64
	}

	TargetUnit struct {
		_              struct{} `cbor:",toarray"`
		Amount         uint64
		OwnerPredicate []byte
	}
)
