package orchestration

type (
	AddVarAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte
	}
)
