package tokens

import (
	"bytes"
	"strings"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var _ types.UnitData = (*NonFungibleTokenTypeData)(nil)
var _ types.UnitData = (*FungibleTokenTypeData)(nil)
var _ types.UnitData = (*NonFungibleTokenData)(nil)
var _ types.UnitData = (*FungibleTokenData)(nil)

type NonFungibleTokenTypeData struct {
	_                        struct{}        `cbor:",toarray"`
	Version                  types.ABVersion `json:"version"`
	Symbol                   string          `json:"symbol"`
	Name                     string          `json:"name"`
	Icon                     *Icon           `json:"icon"`
	ParentTypeID             types.UnitID    `json:"parentTypeId"`             // identifies the parent type that this type derives from; nil indicates there is no parent type
	SubTypeCreationPredicate hex.Bytes       `json:"subTypeCreationPredicate"` // the predicate clause that controls defining new subtypes of this type
	TokenMintingPredicate    hex.Bytes       `json:"tokenMintingPredicate"`    // the predicate clause that controls minting new tokens of this type
	TokenTypeOwnerPredicate  hex.Bytes       `json:"tokenTypeOwnerPredicate"`  // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
	DataUpdatePredicate      hex.Bytes       `json:"dataUpdatePredicate"`      // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their data update predicates
}

type FungibleTokenTypeData struct {
	_                        struct{}        `cbor:",toarray"`
	Version                  types.ABVersion `json:"version"`
	Symbol                   string          `json:"symbol"`
	Name                     string          `json:"name"`
	Icon                     *Icon           `json:"icon"`
	ParentTypeID             types.UnitID    `json:"parentTypeId"`             // identifies the parent type that this type derives from; nil indicates there is no parent type
	DecimalPlaces            uint32          `json:"decimalPlaces"`            // is the number of decimal places to display for values of tokens of this type
	SubTypeCreationPredicate hex.Bytes       `json:"subTypeCreationPredicate"` // the predicate clause that controls defining new subtypes of this type
	TokenMintingPredicate    hex.Bytes       `json:"tokenMintingPredicate"`    // the predicate clause that controls minting new tokens of this type
	TokenTypeOwnerPredicate  hex.Bytes       `json:"tokenTypeOwnerPredicate"`  // the predicate clause that all tokens of this type (and of subtypes of this type) inherit into their owner predicates
}

type NonFungibleTokenData struct {
	_                   struct{}        `cbor:",toarray"`
	Version             types.ABVersion `json:"version"`
	TypeID              types.UnitID    `json:"typeId"`              // the type of this token
	Name                string          `json:"name"`                // the optional long name of this token
	URI                 string          `json:"uri"`                 // the optional URI of an external resource associated with this token
	Data                hex.Bytes       `json:"data"`                // the optional data associated with this token
	OwnerPredicate      hex.Bytes       `json:"ownerPredicate"`      // the owner predicate of this token
	DataUpdatePredicate hex.Bytes       `json:"dataUpdatePredicate"` // the data update predicate;
	Counter             uint64          `json:"counter,string"`      // the transaction counter of this token
}

type FungibleTokenData struct {
	_              struct{}        `cbor:",toarray"`
	Version        types.ABVersion `json:"version"`
	TypeID         types.UnitID    `json:"typeId"`             // the type of this token
	Value          uint64          `json:"value,string"`       // the value of this token
	OwnerPredicate hex.Bytes       `json:"ownerPredicate"`     // the owner predicate of this token
	Counter        uint64          `json:"counter,string"`     // the transaction counter of this token
	MinLifetime    uint64          `json:"minLifetime,string"` // the earliest round number when this token may be deleted if the balance goes to zero
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

func NewFungibleTokenData(typeID types.UnitID, value uint64, ownerPredicate []byte, minLifetime uint64) types.UnitData {
	return &FungibleTokenData{
		TypeID:         typeID,
		Value:          value,
		OwnerPredicate: ownerPredicate,
		MinLifetime:    minLifetime,
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

func (n *NonFungibleTokenTypeData) GetVersion() types.ABVersion {
	if n != nil && n.Version != 0 {
		return n.Version
	}
	return 1
}

func (n *NonFungibleTokenTypeData) MarshalCBOR() ([]byte, error) {
	type alias NonFungibleTokenTypeData
	if n.Version == 0 {
		n.Version = n.GetVersion()
	}
	return cbor.Marshal((*alias)(n))
}

func (n *NonFungibleTokenTypeData) UnmarshalCBOR(data []byte) error {
	type alias NonFungibleTokenTypeData
	if err := cbor.Unmarshal(data, (*alias)(n)); err != nil {
		return err
	}
	return types.EnsureVersion(n, n.Version, 1)
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
		Counter:             n.Counter,
	}
}

func (n *NonFungibleTokenData) GetVersion() types.ABVersion {
	if n != nil && n.Version != 0 {
		return n.Version
	}
	return 1
}

func (n *NonFungibleTokenData) MarshalCBOR() ([]byte, error) {
	type alias NonFungibleTokenData
	if n.Version == 0 {
		n.Version = n.GetVersion()
	}
	return cbor.Marshal((*alias)(n))
}

func (n *NonFungibleTokenData) UnmarshalCBOR(data []byte) error {
	type alias NonFungibleTokenData
	if err := cbor.Unmarshal(data, (*alias)(n)); err != nil {
		return err
	}
	return types.EnsureVersion(n, n.Version, 1)
}

func (n *NonFungibleTokenData) GetCounter() uint64 {
	return n.Counter
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

func (f *FungibleTokenTypeData) GetVersion() types.ABVersion {
	if f != nil && f.Version != 0 {
		return f.Version
	}
	return 1
}

func (b *FungibleTokenTypeData) MarshalCBOR() ([]byte, error) {
	type alias FungibleTokenTypeData
	if b.Version == 0 {
		b.Version = b.GetVersion()
	}
	return cbor.Marshal((*alias)(b))
}

func (b *FungibleTokenTypeData) UnmarshalCBOR(data []byte) error {
	type alias FungibleTokenTypeData
	if err := cbor.Unmarshal(data, (*alias)(b)); err != nil {
		return err
	}
	return types.EnsureVersion(b, b.Version, 1)
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
		TypeID:         bytes.Clone(f.TypeID),
		Value:          f.Value,
		OwnerPredicate: bytes.Clone(f.OwnerPredicate),
		Counter:        f.Counter,
		MinLifetime:    f.MinLifetime,
	}
}

func (f *FungibleTokenData) GetCounter() uint64 {
	return f.Counter
}

func (f *FungibleTokenData) Owner() []byte {
	return f.OwnerPredicate
}

func (f *FungibleTokenData) GetVersion() types.ABVersion {
	if f != nil && f.Version != 0 {
		return f.Version
	}
	return 1
}

func (f *FungibleTokenData) MarshalCBOR() ([]byte, error) {
	type alias FungibleTokenData
	if f.Version == 0 {
		f.Version = f.GetVersion()
	}
	return cbor.Marshal((*alias)(f))
}

func (f *FungibleTokenData) UnmarshalCBOR(data []byte) error {
	type alias FungibleTokenData
	if err := cbor.Unmarshal(data, (*alias)(f)); err != nil {
		return err
	}
	return types.EnsureVersion(f, f.Version, 1)
}
