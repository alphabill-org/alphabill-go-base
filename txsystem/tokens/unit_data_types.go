package tokens

import (
	"bytes"
	"fmt"
	"hash"
	"strings"

	"github.com/alphabill-org/alphabill-go-base/types"
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
	SubTypeCreationPredicate []byte       `json:"subTypeCreationPredicate"` // the predicate clause that controls defining new subtypes of this type
	TokenMintingPredicate    []byte       `json:"tokenMintingPredicate"`    // the predicate clause that controls minting new tokens of this type
	TokenTypeOwnerPredicate  []byte       `json:"tokenTypeOwnerPredicate"`  // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
	DataUpdatePredicate      []byte       `json:"dataUpdatePredicate"`      // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their data update predicates
}

type FungibleTokenTypeData struct {
	_                        struct{}     `cbor:",toarray"`
	Symbol                   string       `json:"symbol"`
	Name                     string       `json:"name"`
	Icon                     *Icon        `json:"icon"`
	ParentTypeID             types.UnitID `json:"parentTypeId"`             // identifies the parent type that this type derives from; nil indicates there is no parent type
	DecimalPlaces            uint32       `json:"decimalPlaces"`            // is the number of decimal places to display for values of tokens of this type
	SubTypeCreationPredicate []byte       `json:"subTypeCreationPredicate"` // the predicate clause that controls defining new subtypes of this type
	TokenMintingPredicate    []byte       `json:"tokenMintingPredicate"`    // the predicate clause that controls minting new tokens of this type
	TokenTypeOwnerPredicate  []byte       `json:"tokenTypeOwnerPredicate"`  // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
}

type NonFungibleTokenData struct {
	_                   struct{}     `cbor:",toarray"`
	TypeID              types.UnitID `json:"typeID"`              // the type of the token
	Name                string       `json:"name"`                // the optional long name of the token
	URI                 string       `json:"uri"`                 // uri is the optional URI of an external resource associated with the token
	Data                []byte       `json:"data"`                // data is the optional data associated with the token.
	DataUpdatePredicate []byte       `json:"dataUpdatePredicate"` // the data update predicate;
	T                   uint64       `json:"lastUpdate,string"`   // the round number of the last transaction with this token;
	Counter             uint64       `json:"counter,string"`      // the transaction counter for this token
	Locked              uint64       `json:"locked,string"`       // locked status of the bill, non-zero value means locked
}

type FungibleTokenData struct {
	_         struct{}     `cbor:",toarray"`
	TokenType types.UnitID `json:"tokenType"`         // the type of the token
	Value     uint64       `json:"value,string"`      // the value of the token
	T         uint64       `json:"lastUpdate,string"` // the partition round number of the last transaction with this token
	Counter   uint64       `json:"counter,string"`    // the transaction counter for this token
	T1        uint64       `json:"t1,string"`         // the minimum lifetime of this token
	Locked    uint64       `json:"locked,string"`     // locked status of the bill, non-zero value means locked
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

func NewNonFungibleTokenData(typeID types.UnitID, attr *MintNonFungibleTokenAttributes, blockNumber, counter uint64) types.UnitData {
	return &NonFungibleTokenData{
		TypeID:              typeID,
		Name:                attr.Name,
		URI:                 attr.URI,
		Data:                attr.Data,
		DataUpdatePredicate: attr.DataUpdatePredicate,
		T:                   blockNumber,
		Counter:             counter,
		Locked:              0,
	}
}

func NewFungibleTokenData(typeID types.UnitID, value, blockNumber, counter, timeout uint64) types.UnitData {
	return &FungibleTokenData{
		TokenType: typeID,
		Value:     value,
		T:         blockNumber,
		Counter:   counter,
		T1:        timeout,
		Locked:    0,
	}
}

func (n *NonFungibleTokenTypeData) Write(hasher hash.Hash) error {
	res, err := types.Cbor.Marshal(n)
	if err != nil {
		return fmt.Errorf("nft type serialization error: %w", err)
	}
	_, err = hasher.Write(res)
	return err
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

func (n *NonFungibleTokenData) Write(hasher hash.Hash) error {
	res, err := types.Cbor.Marshal(n)
	if err != nil {
		return fmt.Errorf("nft data serialization error: %w", err)
	}
	_, err = hasher.Write(res)
	return err
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
		DataUpdatePredicate: bytes.Clone(n.DataUpdatePredicate),
		T:                   n.T,
		Counter:             n.Counter,
		Locked:              n.Locked,
	}
}

func (n *NonFungibleTokenData) GetCounter() uint64 {
	return n.Counter
}

func (n *NonFungibleTokenData) IsLocked() uint64 {
	return n.Locked
}

func (f *FungibleTokenTypeData) Write(hasher hash.Hash) error {
	res, err := types.Cbor.Marshal(f)
	if err != nil {
		return fmt.Errorf("ft type serialization error: %w", err)
	}
	_, err = hasher.Write(res)
	return err
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

func (f *FungibleTokenData) Write(hasher hash.Hash) error {
	res, err := types.Cbor.Marshal(f)
	if err != nil {
		return fmt.Errorf("ft data serialization error: %w", err)
	}
	_, err = hasher.Write(res)
	return err
}

func (f *FungibleTokenData) SummaryValueInput() uint64 {
	return 0
}

func (f *FungibleTokenData) Copy() types.UnitData {
	if f == nil {
		return nil
	}
	return &FungibleTokenData{
		TokenType: bytes.Clone(f.TokenType),
		Value:     f.Value,
		T:         f.T,
		Counter:   f.Counter,
		T1:        f.T1,
		Locked:    f.Locked,
	}
}

func (f *FungibleTokenData) GetCounter() uint64 {
	return f.Counter
}

func (f *FungibleTokenData) IsLocked() uint64 {
	return f.Locked
}
