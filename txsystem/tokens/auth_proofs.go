package tokens

type (
	DefineNonFungibleTokenAuthProof struct {
		_                     struct{} `cbor:",toarray"`
		SubTypeCreationProofs [][]byte // inputs to satisfy the subtype predicates of the parent types
	}

	MintNonFungibleTokenAuthProof struct {
		_                 struct{} `cbor:",toarray"`
		TokenMintingProof []byte   // the input to satisfy the token minting predicate of the type
	}

	TransferNonFungibleTokenAuthProof struct {
		_                    struct{} `cbor:",toarray"`
		OwnerProof           []byte   // input to satisfy the current owner predicate of the token
		TokenTypeOwnerProofs [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	UpdateNonFungibleTokenAuthProof struct {
		_                         struct{} `cbor:",toarray"`
		TokenDataUpdateProof      []byte   // input to satisfy token's data update predicate
		TokenTypeDataUpdateProofs [][]byte // inputs to satisfy the data update predicates inherited from the types
	}

	DefineFungibleTokenAuthProof struct {
		_                     struct{} `cbor:",toarray"`
		SubTypeCreationProofs [][]byte // inputs to satisfy the subtype creation predicates of all parents
	}

	MintFungibleTokenAuthProof struct {
		_                 struct{} `cbor:",toarray"`
		TokenMintingProof []byte   // input to satisfy the token minting predicate of the type
	}

	TransferFungibleTokenAuthProof struct {
		_                    struct{} `cbor:",toarray"`
		OwnerProof           []byte   // input to satisfy the current owner predicate of the token
		TokenTypeOwnerProofs [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	SplitFungibleTokenAuthProof struct {
		_                    struct{} `cbor:",toarray"`
		OwnerProof           []byte   // input to satisfy the current owner predicate of the token
		TokenTypeOwnerProofs [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	BurnFungibleTokenAuthProof struct {
		_                    struct{} `cbor:",toarray"`
		OwnerProof           []byte   // input to satisfy the owner predicate of the source token
		TokenTypeOwnerProofs [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	JoinFungibleTokenAuthProof struct {
		_                    struct{} `cbor:",toarray"`
		OwnerProof           []byte   // input to satisfy the owner predicate of the target token
		TokenTypeOwnerProofs [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	LockTokenAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte   // input to satisfy the owner predicate of the target token
	}

	UnlockTokenAuthProof struct {
		_          struct{} `cbor:",toarray"`
		OwnerProof []byte   // input to satisfy the owner predicate of the target token
	}
)
