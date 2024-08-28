package permissioned

import "github.com/alphabill-org/alphabill-go-base/types"

const (
	PayloadTypeCreateFCR = "createFCR"
	PayloadTypeDeleteFCR = "deleteFCR"
)

type (
	// CreateFeeCreditAttributes is transaction of type "createFCR".
	// The transaction is used to create fee credit records for users.
	// The transaction must be signed by the admin key.
	CreateFeeCreditAttributes struct {
		_ struct{} `cbor:",toarray"`

		FeeCreditOwnerPredicate []byte // the fee credit record owner predicate to be created
	}

	CreateFeeCreditAuthProof struct {
		_ struct{} `cbor:",toarray"`

		OwnerProof []byte // the owner proof signed by admin key
	}

	// DeleteFeeCreditAttributes is transaction of type "deleteFCR".
	// The transaction is used to delete fee credit records created by "createFCR" transactions.
	// The transaction must be signed by the admin key.
	DeleteFeeCreditAttributes struct {
		_ struct{} `cbor:",toarray"`
	}

	DeleteFeeCreditAuthProof struct {
		_ struct{} `cbor:",toarray"`

		OwnerProof []byte // the owner proof signed by admin key
	}
)

func IsFeeCreditTx(tx *types.TransactionOrder) bool {
	typeUrl := tx.PayloadType()
	return typeUrl == PayloadTypeCreateFCR ||
		typeUrl == PayloadTypeDeleteFCR
}
