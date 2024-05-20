package tokens

import (
	"bytes"
	"strings"

	"github.com/alphabill-org/alphabill-go-base/types"
)

const DefaultSystemID types.SystemID = 0x00000002

const (
	PayloadTypeCreateNFTType           = "createNType"
	PayloadTypeMintNFT                 = "createNToken"
	PayloadTypeTransferNFT             = "transNToken"
	PayloadTypeUpdateNFT               = "updateNToken"
	PayloadTypeCreateFungibleTokenType = "createFType"
	PayloadTypeMintFungibleToken       = "createFToken"
	PayloadTypeTransferFungibleToken   = "transFToken"
	PayloadTypeSplitFungibleToken      = "splitFToken"
	PayloadTypeBurnFungibleToken       = "burnFToken"
	PayloadTypeJoinFungibleToken       = "joinFToken"
	PayloadTypeLockToken               = "lockToken"
	PayloadTypeUnlockToken             = "unlockToken"
)

type (
	CreateNonFungibleTokenTypeAttributes struct {
		_                                  struct{}     `cbor:",toarray"`
		Symbol                             string       // the symbol (short name) of this token type; note that the symbols are not guaranteed to be unique;
		Name                               string       // the long name of this token type;
		Icon                               *Icon        // the icon of this token type;
		ParentTypeID                       types.UnitID // identifies the parent type that this type derives from; 0 indicates there is no parent type;
		SubTypeCreationPredicate           []byte       // the predicate clause that controls defining new subtypes of this type;
		TokenCreationPredicate             []byte       // the predicate clause that controls creating new tokens of this type
		InvariantPredicate                 []byte       // the invariant predicate clause that all tokens of this type (and of subtypes of this type) inherit into their bearer predicates;
		DataUpdatePredicate                []byte       // the clause that all tokens of this type (and of subtypes of this type) inherit into their data update predicates
		SubTypeCreationPredicateSignatures [][]byte     // inputs to satisfy the subtype creation predicates of all parents.
	}

	MintNonFungibleTokenAttributes struct {
		_                                struct{}     `cbor:",toarray"`
		Bearer                           []byte       // the initial bearer predicate of the new token
		TypeID                           types.UnitID // the type of the new token
		Name                             string       // the name of the new token
		URI                              string       // the optional URI of an external resource associated with the new token
		Data                             []byte       // the optional data associated with the new token
		DataUpdatePredicate              []byte       // the data update predicate of the new token;
		Nonce                            uint64       // optional nonce
		TokenCreationPredicateSignatures [][]byte     // inputs to satisfy the token creation predicates of all parent types.
	}

	TransferNonFungibleTokenAttributes struct {
		_                            struct{}     `cbor:",toarray"`
		NewBearer                    []byte       // the new bearer predicate of the token
		Nonce                        []byte       // optional nonce
		Counter                      uint64       // the transaction counter of this token
		TypeID                       types.UnitID // identifies the type of the token;
		InvariantPredicateSignatures [][]byte     // inputs to satisfy the token type invariant predicates down the inheritance chain
	}

	UpdateNonFungibleTokenAttributes struct {
		_                    struct{} `cbor:",toarray"`
		Data                 []byte   // the new data to replace the data currently associated with the token
		Counter              uint64   // the transaction counter of this token
		DataUpdateSignatures [][]byte // inputs to satisfy the token data update predicates down the inheritance chain
	}

	CreateFungibleTokenTypeAttributes struct {
		_                                  struct{}     `cbor:",toarray"`
		Symbol                             string       // the symbol (short name) of this token type; note that the symbols are not guaranteed to be unique;
		Name                               string       // the long name of this token type;
		Icon                               *Icon        // the icon of this token type;
		ParentTypeID                       types.UnitID // identifies the parent type that this type derives from; 0 indicates there is no parent type;
		DecimalPlaces                      uint32       // the number of decimal places to display for values of tokens of the new type;
		SubTypeCreationPredicate           []byte       // the predicate clause that controls defining new subtypes of this type;
		TokenCreationPredicate             []byte       // the predicate clause that controls creating new tokens of this type
		InvariantPredicate                 []byte       // the invariant predicate clause that all tokens of this type (and of subtypes of this type) inherit into their bearer predicates;
		SubTypeCreationPredicateSignatures [][]byte     // inputs to satisfy the subtype creation predicates of all parents.
	}

	Icon struct {
		_    struct{} `cbor:",toarray"`
		Type string   `json:"type"` // the MIME content type identifying an image format;
		Data []byte   `json:"data"` // the image in the format specified by type;
	}

	MintFungibleTokenAttributes struct {
		_                                struct{}     `cbor:",toarray"`
		Bearer                           []byte       // the initial bearer predicate of the new token
		TypeID                           types.UnitID // the type of the new token
		Value                            uint64       // the value of the new token
		Nonce                            uint64       // optional nonce
		TokenCreationPredicateSignatures [][]byte     // inputs to satisfy the token creation predicates of all parent types.
	}

	TransferFungibleTokenAttributes struct {
		_                            struct{}     `cbor:",toarray"`
		NewBearer                    []byte       // the initial bearer predicate of the new token
		Value                        uint64       // the value to transfer
		Nonce                        []byte       // optional nonce
		Counter                      uint64       // the transaction counter of this token
		TypeID                       types.UnitID // identifies the type of the token;
		InvariantPredicateSignatures [][]byte     // inputs to satisfy the token type invariant predicates down the inheritance chain
	}

	SplitFungibleTokenAttributes struct {
		_                            struct{}     `cbor:",toarray"`
		NewBearer                    []byte       // the bearer predicate of the new token;
		TargetValue                  uint64       // the value of the new token
		Nonce                        []byte       // optional nonce
		Counter                      uint64       // the transaction counter of this token
		TypeID                       types.UnitID // identifies the type of the token;
		RemainingValue               uint64       // new value of the source token
		InvariantPredicateSignatures [][]byte     // inputs to satisfy the token type invariant predicates down the inheritance chain
	}

	BurnFungibleTokenAttributes struct {
		_                            struct{}     `cbor:",toarray"`
		TypeID                       types.UnitID // identifies the type of the token to burn;
		Value                        uint64       // the value to burn
		TargetTokenID                types.UnitID // the target token identifier in join step
		TargetTokenCounter           uint64       // the current counter value of the target token
		Counter                      uint64       // the transaction counter of this token
		InvariantPredicateSignatures [][]byte     // inputs to satisfy the token type invariant predicates down the inheritance chain
	}

	JoinFungibleTokenAttributes struct {
		_                            struct{}                   `cbor:",toarray"`
		BurnTransactions             []*types.TransactionRecord // the transactions that burned the source tokens;
		Proofs                       []*types.TxProof           // block proofs for burn transactions
		Counter                      uint64                     // the transaction counter of this token
		InvariantPredicateSignatures [][]byte                   // inputs to satisfy the token type invariant predicates down the inheritance chain
	}

	LockTokenAttributes struct {
		_                            struct{} `cbor:",toarray"`
		LockStatus                   uint64   // status of the lock, non-zero value means locked
		Counter                      uint64   // the transaction counter of this token
		InvariantPredicateSignatures [][]byte // inputs to satisfy the token type invariant predicates down the inheritance chain
	}

	UnlockTokenAttributes struct {
		_                            struct{} `cbor:",toarray"`
		Counter                      uint64   // the transaction counter of this token
		InvariantPredicateSignatures [][]byte // inputs to satisfy the token type invariant predicates down the inheritance chain
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

func (b *BurnFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude InvariantPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &BurnFungibleTokenAttributes{
		TypeID:                       b.TypeID,
		Value:                        b.Value,
		TargetTokenID:                b.TargetTokenID,
		TargetTokenCounter:           b.TargetTokenCounter,
		Counter:                      b.Counter,
		InvariantPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (b *BurnFungibleTokenAttributes) SetInvariantPredicateSignatures(signatures [][]byte) {
	b.InvariantPredicateSignatures = signatures
}

func (c *CreateFungibleTokenTypeAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude SubTypeCreationPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &CreateFungibleTokenTypeAttributes{
		Symbol:                             c.Symbol,
		Name:                               c.Name,
		Icon:                               c.Icon,
		ParentTypeID:                       c.ParentTypeID,
		DecimalPlaces:                      c.DecimalPlaces,
		SubTypeCreationPredicate:           c.SubTypeCreationPredicate,
		TokenCreationPredicate:             c.TokenCreationPredicate,
		InvariantPredicate:                 c.InvariantPredicate,
		SubTypeCreationPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (c *CreateFungibleTokenTypeAttributes) SetSubTypeCreationPredicateSignatures(signatures [][]byte) {
	c.SubTypeCreationPredicateSignatures = signatures
}

func (j *JoinFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude InvariantPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &JoinFungibleTokenAttributes{
		BurnTransactions:             j.BurnTransactions,
		Proofs:                       j.Proofs,
		Counter:                      j.Counter,
		InvariantPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (j *JoinFungibleTokenAttributes) SetInvariantPredicateSignatures(signatures [][]byte) {
	j.InvariantPredicateSignatures = signatures
}

func (m *MintFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016
	signatureAttr := &MintFungibleTokenAttributes{
		Bearer:                           m.Bearer,
		TypeID:                           m.TypeID,
		Value:                            m.Value,
		Nonce:                            m.Nonce,
		TokenCreationPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (m *MintFungibleTokenAttributes) SetBearer(bearer []byte) {
	m.Bearer = bearer
}

func (m *MintFungibleTokenAttributes) SetTokenCreationPredicateSignatures(signatures [][]byte) {
	m.TokenCreationPredicateSignatures = signatures
}

func (m *MintFungibleTokenAttributes) GetTypeID() types.UnitID {
	return m.TypeID
}

func (m *MintFungibleTokenAttributes) SetTypeID(typeID types.UnitID) {
	m.TypeID = typeID
}

func (s *SplitFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude InvariantPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &SplitFungibleTokenAttributes{
		NewBearer:                    s.NewBearer,
		TargetValue:                  s.TargetValue,
		Nonce:                        s.Nonce,
		Counter:                      s.Counter,
		TypeID:                       s.TypeID,
		RemainingValue:               s.RemainingValue,
		InvariantPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (s *SplitFungibleTokenAttributes) SetInvariantPredicateSignatures(signatures [][]byte) {
	s.InvariantPredicateSignatures = signatures
}

func (t *TransferFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude InvariantPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &TransferFungibleTokenAttributes{
		NewBearer:                    t.NewBearer,
		Value:                        t.Value,
		Nonce:                        t.Nonce,
		Counter:                      t.Counter,
		TypeID:                       t.TypeID,
		InvariantPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (t *TransferFungibleTokenAttributes) SetInvariantPredicateSignatures(signatures [][]byte) {
	t.InvariantPredicateSignatures = signatures
}

func (l *LockTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude InvariantPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &LockTokenAttributes{
		LockStatus:                   l.LockStatus,
		Counter:                      l.Counter,
		InvariantPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (c *CreateNonFungibleTokenTypeAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude SubTypeCreationPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &CreateNonFungibleTokenTypeAttributes{
		Symbol:                             c.Symbol,
		Name:                               c.Name,
		ParentTypeID:                       c.ParentTypeID,
		SubTypeCreationPredicate:           c.SubTypeCreationPredicate,
		TokenCreationPredicate:             c.TokenCreationPredicate,
		InvariantPredicate:                 c.InvariantPredicate,
		DataUpdatePredicate:                c.DataUpdatePredicate,
		Icon:                               c.Icon,
		SubTypeCreationPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (c *CreateNonFungibleTokenTypeAttributes) SetSubTypeCreationPredicateSignatures(signatures [][]byte) {
	c.SubTypeCreationPredicateSignatures = signatures
}

func (m *MintNonFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude TokenCreationPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &MintNonFungibleTokenAttributes{
		Bearer:                           m.Bearer,
		TypeID:                           m.TypeID,
		Name:                             m.Name,
		URI:                              m.URI,
		Data:                             m.Data,
		DataUpdatePredicate:              m.DataUpdatePredicate,
		Nonce:                            m.Nonce,
		TokenCreationPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (m *MintNonFungibleTokenAttributes) SetBearer(bearer []byte) {
	m.Bearer = bearer
}

func (m *MintNonFungibleTokenAttributes) SetTokenCreationPredicateSignatures(signatures [][]byte) {
	m.TokenCreationPredicateSignatures = signatures
}

func (m *MintNonFungibleTokenAttributes) GetTypeID() types.UnitID {
	return m.TypeID
}

func (m *MintNonFungibleTokenAttributes) SetTypeID(typeID types.UnitID) {
	m.TypeID = typeID
}

func (t *TransferNonFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude SubTypeCreationPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &TransferNonFungibleTokenAttributes{
		NewBearer:                    t.NewBearer,
		Nonce:                        t.Nonce,
		Counter:                      t.Counter,
		TypeID:                       t.TypeID,
		InvariantPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (t *TransferNonFungibleTokenAttributes) SetInvariantPredicateSignatures(signatures [][]byte) {
	t.InvariantPredicateSignatures = signatures
}

func (u *UpdateNonFungibleTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude DataUpdateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &UpdateNonFungibleTokenAttributes{
		Data:                 u.Data,
		Counter:              u.Counter,
		DataUpdateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}

func (u *UpdateNonFungibleTokenAttributes) SetDataUpdateSignatures(signatures [][]byte) {
	u.DataUpdateSignatures = signatures
}

func (l *UnlockTokenAttributes) SigBytes() ([]byte, error) {
	// TODO: AB-1016 exclude InvariantPredicateSignatures from the payload hash because otherwise we have "chicken and egg" problem.
	signatureAttr := &UnlockTokenAttributes{
		Counter:                      l.Counter,
		InvariantPredicateSignatures: nil,
	}
	return types.Cbor.Marshal(signatureAttr)
}
