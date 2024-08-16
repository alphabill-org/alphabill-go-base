package tokens

import (
	"bytes"
	"strings"

	"github.com/alphabill-org/alphabill-go-base/types"
)

const DefaultSystemID types.SystemID = 0x00000002

const (
	PayloadTypeDefineNFT   = "defNT"
	PayloadTypeMintNFT     = "mintNT"
	PayloadTypeTransferNFT = "transNT"
	PayloadTypeUpdateNFT   = "updateNT"

	PayloadTypeDefineFT   = "defFT"
	PayloadTypeMintFT     = "mintFT"
	PayloadTypeTransferFT = "transFT"
	PayloadTypeSplitFT    = "splitFT"
	PayloadTypeBurnFT     = "burnFT"
	PayloadTypeJoinFT     = "joinFT"

	PayloadTypeLockToken   = "lockT"
	PayloadTypeUnlockToken = "unlockT"
)

type (
	DefineNonFungibleTokenAttributes struct {
		_                        struct{}     `cbor:",toarray"`
		Symbol                   string       // the symbol (short name) of this token type; note that the symbols are not guaranteed to be unique
		Name                     string       // the long name of this token type
		Icon                     *Icon        // the optional icon of this token type
		ParentTypeID             types.UnitID // identifies the parent type that this type derives from; nil indicates there is no parent type
		SubTypeCreationPredicate []byte       // the predicate clause that controls defining new subtypes of this type
		TokenCreationPredicate   []byte       // the predicate clause that controls creating new tokens of this type
		TokenTypeOwnerPredicate  []byte       // the predicate clause that all tokens of the new type (and of subtypes of it) inherit into their owner predicates
		DataUpdatePredicate      []byte       // the clause that all tokens of this type (and of subtypes of this type) inherit into their data update predicates
	}

	MintNonFungibleTokenAttributes struct {
		_                   struct{}     `cbor:",toarray"`
		OwnerPredicate      []byte       // the initial owner predicate of the new token
		TypeID              types.UnitID // the type of the new token
		Name                string       // the name of the new token
		URI                 string       // the optional URI of an external resource associated with the new token
		Data                []byte       // the optional data associated with the new token
		DataUpdatePredicate []byte       // the data update predicate of the new token
		Nonce               uint64       // optional nonce
	}

	TransferNonFungibleTokenAttributes struct {
		_                 struct{}     `cbor:",toarray"`
		NewOwnerPredicate []byte       // the new owner predicate of the token
		Nonce             []byte       // optional nonce
		Counter           uint64       // the transaction counter of this token
		TypeID            types.UnitID // identifies the type of the token
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
		TokenCreationPredicate   []byte       // the predicate clause that controls creating new tokens of this type
		TokenTypeOwnerPredicate  []byte       // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
	}

	Icon struct {
		_    struct{} `cbor:",toarray"`
		Type string   `json:"type"` // the MIME content type identifying an image format
		Data []byte   `json:"data"` // the image in the format specified by type
	}

	MintFungibleTokenAttributes struct {
		_              struct{}     `cbor:",toarray"`
		OwnerPredicate []byte       // the initial owner predicate of the new token
		TypeID         types.UnitID // the type of the new token
		Value          uint64       // the value of the new token
		Nonce          uint64       // optional nonce
	}

	TransferFungibleTokenAttributes struct {
		_                 struct{}     `cbor:",toarray"`
		NewOwnerPredicate []byte       // the initial owner predicate of the new token
		Value             uint64       // the value to transfer
		Nonce             []byte       // optional nonce
		Counter           uint64       // the transaction counter of this token
		TypeID            types.UnitID // identifies the type of the token
	}

	SplitFungibleTokenAttributes struct {
		_                 struct{}     `cbor:",toarray"`
		NewOwnerPredicate []byte       // the owner predicate of the new token
		TargetValue       uint64       // the value of the new token
		Nonce             []byte       // optional nonce
		Counter           uint64       // the transaction counter of this token
		TypeID            types.UnitID // identifies the type of the token
		RemainingValue    uint64       // new value of the source token
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
		_                struct{}                   `cbor:",toarray"`
		BurnTransactions []*types.TransactionRecord // the transactions that burned the source tokens
		Proofs           []*types.TxProof           // block proofs for burn transactions
		Counter          uint64                     // the transaction counter of this token
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
