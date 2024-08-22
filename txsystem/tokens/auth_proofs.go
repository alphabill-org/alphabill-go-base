package tokens

type (
	DefineNonFungibleTokenAuthProof struct {
		_                                  struct{} `cbor:",toarray"`
		SubTypeCreationPredicateSignatures [][]byte // inputs to satisfy the subtype predicates of the parent types
	}

	MintNonFungibleTokenAuthProof struct {
		_                              struct{} `cbor:",toarray"`
		TokenMintingPredicateSignature []byte   // the input to satisfy the token minting predicate of the type
	}

	TransferNonFungibleTokenAuthProof struct {
		_                                 struct{} `cbor:",toarray"`
		OwnerPredicateSignature           []byte   // input to satisfy the current owner predicate of the token
		TokenTypeOwnerPredicateSignatures [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	UpdateNonFungibleTokenAuthProof struct {
		_                                      struct{} `cbor:",toarray"`
		TokenDataUpdatePredicateSignature      []byte   // input to satisfy token's data update predicate
		TokenTypeDataUpdatePredicateSignatures [][]byte // inputs to satisfy the data update predicates inherited from the types
	}

	DefineFungibleTokenAuthProof struct {
		_                                  struct{} `cbor:",toarray"`
		SubTypeCreationPredicateSignatures [][]byte // inputs to satisfy the subtype creation predicates of all parents
	}

	MintFungibleTokenAuthProof struct {
		_                              struct{} `cbor:",toarray"`
		TokenMintingPredicateSignature []byte   // input to satisfy the token minting predicate of the type
	}

	TransferFungibleTokenAuthProof struct {
		_                                 struct{} `cbor:",toarray"`
		OwnerPredicateSignature           []byte   // input to satisfy the current owner predicate of the token
		TokenTypeOwnerPredicateSignatures [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	SplitFungibleTokenAuthProof struct {
		_                                 struct{} `cbor:",toarray"`
		OwnerPredicateSignature           []byte   // input to satisfy the current owner predicate of the token
		TokenTypeOwnerPredicateSignatures [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	BurnFungibleTokenAuthProof struct {
		_                                 struct{} `cbor:",toarray"`
		OwnerPredicateSignature           []byte   // input to satisfy the owner predicate of the source token
		TokenTypeOwnerPredicateSignatures [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	JoinFungibleTokenAuthProof struct {
		_                                 struct{} `cbor:",toarray"`
		OwnerPredicateSignature           []byte   // input to satisfy the owner predicate of the target token
		TokenTypeOwnerPredicateSignatures [][]byte // inputs to satisfy the owner predicates inherited from the types
	}

	LockTokenAuthProof struct {
		_                       struct{} `cbor:",toarray"`
		OwnerPredicateSignature []byte   // input to satisfy the owner predicate of the target token
	}

	UnlockTokenAuthProof struct {
		_                       struct{} `cbor:",toarray"`
		OwnerPredicateSignature []byte   // input to satisfy the owner predicate of the target token
	}
)
