package tokens

import (
	"bytes"
	"strings"

	"github.com/alphabill-org/alphabill-go-base/types"
)

const DefaultPartitionID types.PartitionID = 2

const (
	TransactionTypeDefineFT    uint16 = 1
	TransactionTypeDefineNFT   uint16 = 2
	TransactionTypeMintFT      uint16 = 3
	TransactionTypeMintNFT     uint16 = 4
	TransactionTypeTransferFT  uint16 = 5
	TransactionTypeTransferNFT uint16 = 6
	TransactionTypeLockToken   uint16 = 7
	TransactionTypeUnlockToken uint16 = 8
	TransactionTypeSplitFT     uint16 = 9
	TransactionTypeBurnFT      uint16 = 10
	TransactionTypeJoinFT      uint16 = 11
	TransactionTypeUpdateNFT   uint16 = 12
)

type (
	DefineNonFungibleTokenAttributes struct {
		_                        struct{}     `cbor:",toarray"`
		Symbol                   string       // the symbol (short name) of this token type; note that the symbols are not guaranteed to be unique
		Name                     string       // the long name of this token type
		Icon                     *Icon        // the optional icon of this token type
		ParentTypeID             types.UnitID // identifies the parent type that this type derives from; nil indicates there is no parent type
		SubTypeCreationPredicate []byte       // the predicate clause that controls defining new subtypes of this type
		TokenMintingPredicate    []byte       // the predicate clause that controls minting new tokens of this type
		TokenTypeOwnerPredicate  []byte       // the predicate clause that all tokens of the new type (and of subtypes of it) inherit into their owner predicates
		DataUpdatePredicate      []byte       // the clause that all tokens of this type (and of subtypes of this type) inherit into their data update predicates
	}

	MintNonFungibleTokenAttributes struct {
		_                   struct{}     `cbor:",toarray"`
		TypeID              types.UnitID // the type of the new token
		Name                string       // the name of the new token
		URI                 string       // the optional URI of an external resource associated with the new token
		Data                []byte       // the optional data associated with the new token
		OwnerPredicate      []byte       // the initial owner predicate of the new token
		DataUpdatePredicate []byte       // the data update predicate of the new token
		Nonce               uint64       // optional nonce
	}

	TransferNonFungibleTokenAttributes struct {
		_                 struct{}     `cbor:",toarray"`
		TypeID            types.UnitID // identifies the type of the token
		NewOwnerPredicate []byte       // the new owner predicate of the token
		Counter           uint64       // the transaction counter of this token
	}

	UpdateNonFungibleTokenAttributes struct {
		_       struct{} `cbor:",toarray"`
		Data    []byte   // the new data to replace the data currently associated with the token
		Counter uint64   // the transaction counter of this token
	}

	DefineFungibleTokenAttributes struct {
		_                        struct{}     `cbor:",toarray"`
		Symbol                   string       // the symbol (short name) of this token type; note that the symbols are not guaranteed to be unique
		Name                     string       // the long name of this token type
		Icon                     *Icon        // the icon of this token type
		ParentTypeID             types.UnitID // identifies the parent type that this type derives from; nil indicates there is no parent type
		DecimalPlaces            uint32       // the number of decimal places to display for values of tokens of the new type
		SubTypeCreationPredicate []byte       // the predicate clause that controls defining new subtypes of this type
		TokenMintingPredicate    []byte       // the predicate clause that controls minting new tokens of this type
		TokenTypeOwnerPredicate  []byte       // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
	}

	Icon struct {
		_    struct{} `cbor:",toarray"`
		Type string   `json:"type"` // the MIME content type identifying an image format
		Data []byte   `json:"data"` // the image in the format specified by type
	}

	MintFungibleTokenAttributes struct {
		_              struct{}     `cbor:",toarray"`
		TypeID         types.UnitID // the type of the new token
		Value          uint64       // the value of the new token
		OwnerPredicate []byte       // the initial owner predicate of the new token
		Nonce          uint64       // optional nonce
	}

	TransferFungibleTokenAttributes struct {
		_                 struct{}     `cbor:",toarray"`
		TypeID            types.UnitID // identifies the type of the token
		Value             uint64       // the value to transfer
		NewOwnerPredicate []byte       // the initial owner predicate of the new token
		Counter           uint64       // the transaction counter of this token
	}

	SplitFungibleTokenAttributes struct {
		_                 struct{}     `cbor:",toarray"`
		TypeID            types.UnitID // identifies the type of the token
		TargetValue       uint64       // the value of the new token
		NewOwnerPredicate []byte       // the owner predicate of the new token
		Counter           uint64       // the transaction counter of this token
	}

	BurnFungibleTokenAttributes struct {
		_                  struct{}     `cbor:",toarray"`
		TypeID             types.UnitID // identifies the type of the token to burn
		Value              uint64       // the value to burn
		TargetTokenID      types.UnitID // the target token identifier in join step
		TargetTokenCounter uint64       // the current counter value of the target token
		Counter            uint64       // the transaction counter of this token
	}

	JoinFungibleTokenAttributes struct {
		_               struct{}               `cbor:",toarray"`
		BurnTokenProofs []*types.TxRecordProof // the transaction records and proofs that burned the source tokens
	}

	LockTokenAttributes struct {
		_          struct{} `cbor:",toarray"`
		LockStatus uint64   // status of the lock, non-zero value means locked
		Counter    uint64   // the transaction counter of this token
	}

	UnlockTokenAttributes struct {
		_       struct{} `cbor:",toarray"`
		Counter uint64   // the transaction counter of this token
	}
)

func (i *Icon) Copy() *Icon {
	if i == nil {
		return nil
	}
	return &Icon{
		Type: strings.Clone(i.Type),
		Data: bytes.Clone(i.Data),
	}
}
