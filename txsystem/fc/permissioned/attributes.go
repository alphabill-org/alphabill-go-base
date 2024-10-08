package permissioned

import "github.com/alphabill-org/alphabill-go-base/types"

const (
	TransactionTypeSetFeeCredit    uint16 = 20
	TransactionTypeDeleteFeeCredit uint16 = 21
)

type (
	// SetFeeCreditAttributes is transaction of type "setFC".
	// The transaction is used to add fee credit records for users.
	// The transaction must be signed by the admin key.
	SetFeeCreditAttributes struct {
		_ struct{} `cbor:",toarray"`

		OwnerPredicate []byte  // the owner predicate to be set to the fee credit record
		Amount         uint64  // the fee credit amount to be added
		Counter        *uint64 // the transaction counter of the target fee credit record, or nil if the record does not exist yet
	}

	// DeleteFeeCreditAttributes is transaction of type "delFC".
	// The transaction is used to delete fee credit records created by "setFC" transactions.
	// The transaction must be signed by the admin key.
	DeleteFeeCreditAttributes struct {
		_ struct{} `cbor:",toarray"`

		Counter uint64 // the transaction counter of the target fee credit record
	}
)

func IsFeeCreditTx(tx *types.TransactionOrder) bool {
	if tx == nil {
		return false
	}
	return tx.Type >= TransactionTypeSetFeeCredit && tx.Type <= TransactionTypeDeleteFeeCredit
}
