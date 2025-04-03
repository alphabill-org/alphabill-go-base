package money

type (
	TransferAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	SplitAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	TransferDCAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}

	SwapDCAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}
)
