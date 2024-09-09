package permissioned

type (
	SetFeeCreditAuthProof struct {
		_ struct{} `cbor:",toarray"`

		OwnerProof []byte // the owner proof signed by admin key
	}

	DeleteFeeCreditAuthProof struct {
		_ struct{} `cbor:",toarray"`

		OwnerProof []byte // the owner proof signed by admin key
	}
)
