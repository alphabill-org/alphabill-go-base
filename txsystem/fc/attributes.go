package fc

import (
	"github.com/alphabill-org/alphabill-go-base/types"
)

const (
	TransactionTypeTransferFeeCredit uint16 = 14
	TransactionTypeReclaimFeeCredit  uint16 = 15
	TransactionTypeAddFeeCredit      uint16 = 16
	TransactionTypeCloseFeeCredit    uint16 = 17
)

type (
	AddFeeCreditAttributes struct {
		_                       struct{}             `cbor:",toarray"`
		FeeCreditOwnerPredicate []byte               // target fee credit record owner predicate
		FeeCreditTransferProof  *types.TxRecordProof // transaction proof of "transfer fee credit" transaction
	}

	TransferFeeCreditAttributes struct {
		_                  struct{}          `cbor:",toarray"`
		Amount             uint64            // amount to transfer
		TargetPartitionID  types.PartitionID // partition identifier of the target partition
		TargetRecordID     []byte            // unit id of the corresponding “add fee credit” transaction
		LatestAdditionTime uint64            // latest round when the corresponding “add fee credit” transaction can be executed in the target system
		TargetUnitCounter  *uint64           // the transaction counter of the target unit, or nil if the record does not exist yet
		Counter            uint64            // the transaction counter of this unit
	}

	CloseFeeCreditAttributes struct {
		_ struct{} `cbor:",toarray"`

		Amount            uint64 // current balance of the fee credit record
		TargetUnitID      []byte // target unit id in money partition
		TargetUnitCounter uint64 // the current transaction counter of the target unit in money partition
		Counter           uint64 // the transaction counter of this fee credit record
	}

	ReclaimFeeCreditAttributes struct {
		_                   struct{}             `cbor:",toarray"`
		CloseFeeCreditProof *types.TxRecordProof // transaction proof of "close fee credit" transaction
	}

	LockFeeCreditAttributes struct {
		_       struct{} `cbor:",toarray"`
		Counter uint64   // the transaction counter of the target unit
	}

	UnlockFeeCreditAttributes struct {
		_       struct{} `cbor:",toarray"`
		Counter uint64   // the transaction counter of the target unit
	}
)

func IsFeeCreditTx(tx *types.TransactionOrder) bool {
	if tx == nil {
		return false
	}
	return tx.Type == TransactionTypeTransferFeeCredit ||
		tx.Type == TransactionTypeReclaimFeeCredit ||
		tx.Type == TransactionTypeAddFeeCredit ||
		tx.Type == TransactionTypeCloseFeeCredit
}
