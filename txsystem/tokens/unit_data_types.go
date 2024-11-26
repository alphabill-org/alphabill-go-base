package tokens

import (
	"bytes"
	"strings"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var _ types.UnitData = (*NonFungibleTokenTypeData)(nil)
var _ types.UnitData = (*FungibleTokenTypeData)(nil)
var _ types.UnitData = (*NonFungibleTokenData)(nil)
var _ types.UnitData = (*FungibleTokenData)(nil)

type NonFungibleTokenTypeData struct {
	_                        struct{}     `cbor:",toarray"`
	Symbol                   string       `json:"symbol"`
	Name                     string       `json:"name"`
	Icon                     *Icon        `json:"icon"`
	ParentTypeID             types.UnitID `json:"parentTypeId"`             // identifies the parent type that this type derives from; nil indicates there is no parent type
	SubTypeCreationPredicate hex.Bytes    `json:"subTypeCreationPredicate"` // the predicate clause that controls defining new subtypes of this type
	TokenMintingPredicate    hex.Bytes    `json:"tokenMintingPredicate"`    // the predicate clause that controls minting new tokens of this type
	TokenTypeOwnerPredicate  hex.Bytes    `json:"tokenTypeOwnerPredicate"`  // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
	DataUpdatePredicate      hex.Bytes    `json:"dataUpdatePredicate"`      // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their data update predicates
}

type FungibleTokenTypeData struct {
	_                        struct{}     `cbor:",toarray"`
	Symbol                   string       `json:"symbol"`
	Name                     string       `json:"name"`
	Icon                     *Icon        `json:"icon"`
	ParentTypeID             types.UnitID `json:"parentTypeId"`             // identifies the parent type that this type derives from; nil indicates there is no parent type
	DecimalPlaces            uint32       `json:"decimalPlaces"`            // is the number of decimal places to display for values of tokens of this type
	SubTypeCreationPredicate hex.Bytes    `json:"subTypeCreationPredicate"` // the predicate clause that controls defining new subtypes of this type
	TokenMintingPredicate    hex.Bytes    `json:"tokenMintingPredicate"`    // the predicate clause that controls minting new tokens of this type
	TokenTypeOwnerPredicate  hex.Bytes    `json:"tokenTypeOwnerPredicate"`  // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
}

type NonFungibleTokenData struct {
	_                   struct{}     `cbor:",toarray"`
	TypeID              types.UnitID `json:"typeID"`              // the type of this token
	Name                string       `json:"name"`                // the optional long name of this token
	URI                 string       `json:"uri"`                 // the optional URI of an external resource associated with this token
	Data                hex.Bytes    `json:"data"`                // the optional data associated with this token
	OwnerPredicate      hex.Bytes    `json:"ownerPredicate"`      // the owner predicate of this token
	DataUpdatePredicate hex.Bytes    `json:"dataUpdatePredicate"` // the data update predicate;
	Locked              uint64       `json:"locked,string"`       // the lock status of this token (non-zero value means locked)
	Counter             uint64       `json:"counter,string"`      // the transaction counter of this token
}

type FungibleTokenData struct {
	_              struct{}     `cbor:",toarray"`
	TokenType      types.UnitID `json:"tokenType"`      // the type of this token
	Value          uint64       `json:"value,string"`   // the value of this token
	OwnerPredicate hex.Bytes    `json:"ownerPredicate"` // the owner predicate of this token
	Locked         uint64       `json:"locked,string"`  // the lock status of this token (non-zero value means locked)
	Counter        uint64       `json:"counter,string"` // the transaction counter of this token
	Timeout        uint64       `json:"timeout,string"` // the earliest round number when this token may be deleted if the balance goes to zero
}

func NewFungibleTokenTypeData(attr *DefineFungibleTokenAttributes) types.UnitData {
	return &FungibleTokenTypeData{
		Symbol:                   attr.Symbol,
		Name:                     attr.Name,
		Icon:                     attr.Icon,
		ParentTypeID:             attr.ParentTypeID,
		DecimalPlaces:            attr.DecimalPlaces,
		SubTypeCreationPredicate: attr.SubTypeCreationPredicate,
		TokenMintingPredicate:    attr.TokenMintingPredicate,
		TokenTypeOwnerPredicate:  attr.TokenTypeOwnerPredicate,
	}
}

func NewNonFungibleTokenTypeData(attr *DefineNonFungibleTokenAttributes) types.UnitData {
	return &NonFungibleTokenTypeData{
		Symbol:                   attr.Symbol,
		Name:                     attr.Name,
		Icon:                     attr.Icon,
		ParentTypeID:             attr.ParentTypeID,
		SubTypeCreationPredicate: attr.SubTypeCreationPredicate,
		TokenMintingPredicate:    attr.TokenMintingPredicate,
		TokenTypeOwnerPredicate:  attr.TokenTypeOwnerPredicate,
		DataUpdatePredicate:      attr.DataUpdatePredicate,
	}
}

func NewNonFungibleTokenData(typeID types.UnitID, attr *MintNonFungibleTokenAttributes) types.UnitData {
	return &NonFungibleTokenData{
		TypeID:              typeID,
		Name:                attr.Name,
		URI:                 attr.URI,
		Data:                attr.Data,
		OwnerPredicate:      attr.OwnerPredicate,
		DataUpdatePredicate: attr.DataUpdatePredicate,
	}
}

func NewFungibleTokenData(typeID types.UnitID, value uint64, ownerPredicate []byte, timeout uint64) types.UnitData {
	return &FungibleTokenData{
		TokenType:      typeID,
		Value:          value,
		OwnerPredicate: ownerPredicate,
		Timeout:        timeout,
	}
}

func (n *NonFungibleTokenTypeData) Write(hasher abhash.Hasher) {
	hasher.Write(n)
}

func (n *NonFungibleTokenTypeData) SummaryValueInput() uint64 {
	return 0
}

func (n *NonFungibleTokenTypeData) Copy() types.UnitData {
	if n == nil {
		return nil
	}
	return &NonFungibleTokenTypeData{
		Symbol:                   strings.Clone(n.Symbol),
		Name:                     strings.Clone(n.Name),
		Icon:                     n.Icon.Copy(),
		ParentTypeID:             bytes.Clone(n.ParentTypeID),
		SubTypeCreationPredicate: bytes.Clone(n.SubTypeCreationPredicate),
		TokenMintingPredicate:    bytes.Clone(n.TokenMintingPredicate),
		TokenTypeOwnerPredicate:  bytes.Clone(n.TokenTypeOwnerPredicate),
		DataUpdatePredicate:      bytes.Clone(n.DataUpdatePredicate),
	}
}

func (n *NonFungibleTokenTypeData) Owner() []byte {
	return nil
}

func (n *NonFungibleTokenData) Write(hasher abhash.Hasher) {
	hasher.Write(n)
}

func (n *NonFungibleTokenData) SummaryValueInput() uint64 {
	return 0
}

func (n *NonFungibleTokenData) Copy() types.UnitData {
	if n == nil {
		return nil
	}
	return &NonFungibleTokenData{
		TypeID:              bytes.Clone(n.TypeID),
		Name:                strings.Clone(n.Name),
		URI:                 strings.Clone(n.URI),
		Data:                bytes.Clone(n.Data),
		OwnerPredicate:      bytes.Clone(n.OwnerPredicate),
		DataUpdatePredicate: bytes.Clone(n.DataUpdatePredicate),
		Locked:              n.Locked,
		Counter:             n.Counter,
	}
}

func (n *NonFungibleTokenData) GetCounter() uint64 {
	return n.Counter
}

func (n *NonFungibleTokenData) IsLocked() uint64 {
	return n.Locked
}

func (n *NonFungibleTokenData) Owner() []byte {
	return n.OwnerPredicate
}

func (f *FungibleTokenTypeData) Write(hasher abhash.Hasher) {
	hasher.Write(f)
}

func (f *FungibleTokenTypeData) SummaryValueInput() uint64 {
	return 0
}

func (f *FungibleTokenTypeData) Copy() types.UnitData {
	if f == nil {
		return nil
	}
	return &FungibleTokenTypeData{
		Symbol:                   strings.Clone(f.Symbol),
		Name:                     strings.Clone(f.Name),
		Icon:                     f.Icon.Copy(),
		ParentTypeID:             bytes.Clone(f.ParentTypeID),
		DecimalPlaces:            f.DecimalPlaces,
		SubTypeCreationPredicate: bytes.Clone(f.SubTypeCreationPredicate),
		TokenMintingPredicate:    bytes.Clone(f.TokenMintingPredicate),
		TokenTypeOwnerPredicate:  bytes.Clone(f.TokenTypeOwnerPredicate),
	}
}

func (f *FungibleTokenTypeData) Owner() []byte {
	return nil
}

func (f *FungibleTokenData) Write(hasher abhash.Hasher) {
	hasher.Write(f)
}

func (f *FungibleTokenData) SummaryValueInput() uint64 {
	return 0
}

func (f *FungibleTokenData) Copy() types.UnitData {
	if f == nil {
		return nil
	}
	return &FungibleTokenData{
		TokenType:      bytes.Clone(f.TokenType),
		Value:          f.Value,
		OwnerPredicate: bytes.Clone(f.OwnerPredicate),
		Locked:         f.Locked,
		Counter:        f.Counter,
		Timeout:        f.Timeout,
	}
}

func (f *FungibleTokenData) GetCounter() uint64 {
	return f.Counter
}

func (f *FungibleTokenData) IsLocked() uint64 {
	return f.Locked
}

func (f *FungibleTokenData) Owner() []byte {
	return f.OwnerPredicate
}
