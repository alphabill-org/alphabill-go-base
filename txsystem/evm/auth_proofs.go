package evm

type (
	TxAuthProof struct {
		_ struct{} `cbor:",toarray"`

		OwnerProof []byte
	}
)
