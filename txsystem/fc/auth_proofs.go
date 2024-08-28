package fc

type (
	TransferFeeCreditAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	AddFeeCreditAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	CloseFeeCreditAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	ReclaimFeeCreditAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	LockFeeCreditAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	UnlockFeeCreditAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}
)
