package fc

import (
	"github.com/alphabill-org/alphabill-go-base/types"
)

const (
	PayloadTypeAddFeeCredit      = "addFC"
	PayloadTypeCloseFeeCredit    = "closeFC"
	PayloadTypeReclaimFeeCredit  = "reclFC"
	PayloadTypeTransferFeeCredit = "transFC"
	PayloadTypeLockFeeCredit     = "lockFC"
	PayloadTypeUnlockFeeCredit   = "unlockFC"
)

type (
	AddFeeCreditAttributes struct {
		_                       struct{}                 `cbor:",toarray"`
		FeeCreditOwnerCondition []byte                   // target fee credit record owner condition
		FeeCreditTransfer       *types.TransactionRecord // bill transfer record of type "transfer fee credit"
		FeeCreditTransferProof  *types.TxProof           // transaction proof of "transfer fee credit" transaction
	}

	TransferFeeCreditAttributes struct {
		_                      struct{}       `cbor:",toarray"`
		Amount                 uint64         // amount to transfer
		TargetSystemIdentifier types.SystemID // system_identifier of the target partition
		TargetRecordID         []byte         // unit id of the corresponding “add fee credit” transaction
		LatestAdditionTime     uint64         // latest round when the corresponding “add fee credit” transaction can be executed in the target system
		TargetUnitCounter      *uint64        // the transaction counter of the target unit, or nil if the record does not exist yet
		Counter                uint64         // the transaction counter of this unit
	}

	CloseFeeCreditAttributes struct {
		_ struct{} `cbor:",toarray"`

		Amount            uint64 // current balance of the fee credit record
		TargetUnitID      []byte // target unit id in money partition
		TargetUnitCounter uint64 // the current transaction counter of the target unit in money partition
	}

	ReclaimFeeCreditAttributes struct {
		_                      struct{}                 `cbor:",toarray"`
		CloseFeeCreditTransfer *types.TransactionRecord // bill transfer record of type "close fee credit"
		CloseFeeCreditProof    *types.TxProof           // transaction proof of "close fee credit" transaction
		Counter                uint64                   // the transaction counter of this unit
	}

	LockFeeCreditAttributes struct {
		_          struct{} `cbor:",toarray"`
		LockStatus uint64   // status of the lock, non-zero value means locked
		Counter    uint64   // the transaction counter of the target unit
	}

	UnlockFeeCreditAttributes struct {
		_       struct{} `cbor:",toarray"`
		Counter uint64   // the transaction counter of the target unit
	}
)

func IsFeeCreditTx(tx *types.TransactionOrder) bool {
	typeUrl := tx.PayloadType()
	return typeUrl == PayloadTypeTransferFeeCredit ||
		typeUrl == PayloadTypeAddFeeCredit ||
		typeUrl == PayloadTypeCloseFeeCredit ||
		typeUrl == PayloadTypeReclaimFeeCredit ||
		typeUrl == PayloadTypeLockFeeCredit ||
		typeUrl == PayloadTypeUnlockFeeCredit
}
