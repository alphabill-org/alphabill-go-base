package nop

type (
	AuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}
)
