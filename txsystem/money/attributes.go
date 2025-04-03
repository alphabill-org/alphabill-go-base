package money

import (
	"github.com/alphabill-org/alphabill-go-base/types"
)

const (
	PartitionTypeID    types.PartitionTypeID = 1
	DefaultPartitionID types.PartitionID     = 1

	TransactionTypeTransfer uint16 = 1
	TransactionTypeSplit    uint16 = 2
	TransactionTypeTransDC  uint16 = 3
	TransactionTypeSwapDC   uint16 = 4
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

	TargetUnit struct {
		_              struct{} `cbor:",toarray"`
		Amount         uint64
		OwnerPredicate []byte
	}
)
