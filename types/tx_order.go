package types

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

const (
	StateUnlockRollback StateUnlockProofKind = iota
	StateUnlockExecute
)

var (
	ErrTransactionRecordIsNil = errors.New("transaction record is nil")
	ErrTransactionOrderIsNil  = errors.New("transaction order is nil")
	ErrServerMetadataIsNil    = errors.New("server metadata is nil")
)

type (
	TransactionOrder struct {
		_           struct{} `cbor:",toarray"`
		Version     ABVersion
		Payload                  // the embedded Payload field is "flattened" in CBOR array
		StateUnlock []byte       // two CBOR data items: [0|1]+[<state lock/rollback predicate input>]
		AuthProof   cbor.RawCBOR // transaction type specific signatures/authorisation proofs
		FeeProof    []byte
	}

	// Payload helper struct for transaction signing.
	// Includes all TransactionOrder fields except for the signatures themselves (StateUnlock, AuthProof and FeeProof).
	// Payload is an embedded field of TransactionOrder so that the fields get "flattened" in CBOR encoding.
	Payload struct {
		_              struct{} `cbor:",toarray"`
		NetworkID      NetworkID
		PartitionID    PartitionID
		UnitID         UnitID
		Type           uint16       // transaction type, ie mint, transfer,...
		Attributes     cbor.RawCBOR // transaction type specific attributes
		StateLock      *StateLock
		ClientMetadata *ClientMetadata // metadata about the transaction added by the client
	}

	StateLock struct {
		_                  struct{} `cbor:",toarray"`
		ExecutionPredicate []byte   // predicate for executing state locked Tx
		RollbackPredicate  []byte   // predicate for discarding state locked Tx
	}

	ClientMetadata struct {
		_                 struct{} `cbor:",toarray"`
		Timeout           uint64
		MaxTransactionFee uint64
		FeeCreditRecordID []byte
		ReferenceNumber   []byte
	}

	PredicateBytes = hex.Bytes

	StateLockProofSigData struct {
		_       struct{} `cbor:",toarray"`
		Version ABVersion
		Payload
	}

	AuthProofSigData struct {
		_       struct{} `cbor:",toarray"`
		Version ABVersion
		Payload
		StateUnlock []byte
	}

	FeeProofSigData struct {
		_       struct{} `cbor:",toarray"`
		Version ABVersion
		Payload
		StateUnlock []byte
		AuthProof   cbor.RawCBOR
	}

	StateUnlockProofKind byte
)

func (t *TransactionOrder) StateLockProofSigBytes() ([]byte, error) {
	if t == nil {
		return nil, ErrTransactionOrderIsNil
	}
	stateLockProof := StateLockProofSigData{Version: t.Version, Payload: t.Payload}
	stateLockProofCBOR, err := cbor.Marshal(stateLockProof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state lock sig bytes: %w", err)
	}
	return stateLockProofCBOR, nil
}

func (t *TransactionOrder) AuthProofSigBytes() ([]byte, error) {
	if t == nil {
		return nil, ErrTransactionOrderIsNil
	}
	authProof := AuthProofSigData{Version: t.Version, Payload: t.Payload, StateUnlock: t.StateUnlock}
	authProofCBOR, err := cbor.Marshal(authProof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth proof sig bytes: %w", err)
	}
	return authProofCBOR, nil
}

func (t *TransactionOrder) FeeProofSigBytes() ([]byte, error) {
	if t == nil {
		return nil, ErrTransactionOrderIsNil
	}
	feeProof := FeeProofSigData{Version: t.Version, Payload: t.Payload, StateUnlock: t.StateUnlock, AuthProof: t.AuthProof}
	feeProofCBOR, err := cbor.Marshal(feeProof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal fee proof sig bytes: %w", err)
	}
	return feeProofCBOR, nil
}

func (t *TransactionOrder) UnmarshalAuthProof(v any) error {
	if t == nil {
		return ErrTransactionOrderIsNil
	}
	return cbor.Unmarshal(t.AuthProof, v)
}

func (t *TransactionOrder) Hash(algorithm crypto.Hash) ([]byte, error) {
	h := abhash.New(algorithm.New())
	h.Write(t)
	return h.Sum()
}

// SetAuthProof converts provided authProof struct to CBOR and sets the AuthProof field.
func (t *TransactionOrder) SetAuthProof(authProof any) error {
	if t == nil {
		return ErrTransactionOrderIsNil
	}
	authProofCBOR, err := cbor.Marshal(authProof)
	if err != nil {
		return fmt.Errorf("marshaling auth proof: %w", err)
	}
	t.AuthProof = authProofCBOR
	return nil
}

/*
SetAttributes serializes "attr" and assigns the result to payload's Attributes field.
The "attr" is expected to be one of the transaction attribute structs but there is
no validation!
The TransactionOrder.UnmarshalAttributes can be used to decode the attributes.
*/
func (t *TransactionOrder) SetAttributes(attr any) error {
	if t == nil {
		return ErrTransactionOrderIsNil
	}
	attrCBOR, err := cbor.Marshal(attr)
	if err != nil {
		return fmt.Errorf("marshaling %T as tx attributes: %w", attr, err)
	}
	t.Attributes = attrCBOR
	return nil
}

func (t *TransactionOrder) UnmarshalAttributes(v any) error {
	if t == nil {
		return ErrTransactionOrderIsNil
	}
	return cbor.Unmarshal(t.Attributes, v)
}

func (t *TransactionOrder) HasStateLock() bool {
	return t != nil && t.StateLock != nil
}

func (t *TransactionOrder) GetNetworkID() NetworkID {
	if t == nil {
		return 0
	}
	return t.NetworkID
}

func (t *TransactionOrder) GetPartitionID() PartitionID {
	if t == nil {
		return 0
	}
	return t.PartitionID
}

func (t *TransactionOrder) GetUnitID() UnitID {
	if t == nil {
		return nil
	}
	return t.UnitID
}

func (t *TransactionOrder) Timeout() uint64 {
	if t == nil {
		return 0
	}
	return t.ClientMetadata.GetTimeout()
}

func (t *TransactionOrder) FeeCreditRecordID() []byte {
	if t == nil {
		return nil
	}
	return t.ClientMetadata.GetFeeCreditRecordID()
}

func (t *TransactionOrder) MaxFee() uint64 {
	if t == nil {
		return 0
	}
	return t.ClientMetadata.GetMaxFee()
}

func (t *TransactionOrder) ReferenceNumber() []byte {
	if t == nil {
		return nil
	}
	return t.ClientMetadata.GetReferenceNumber()
}

func (t *TransactionOrder) GetVersion() ABVersion {
	if t == nil || t.Version == 0 {
		return 1
	}
	return t.Version
}

func (t *TransactionOrder) MarshalCBOR() ([]byte, error) {
	type alias TransactionOrder
	if t.Version == 0 {
		t.Version = t.GetVersion()
	}
	return cbor.MarshalTaggedValue(TransactionOrderTag, (*alias)(t))
}

func (t *TransactionOrder) UnmarshalCBOR(data []byte) error {
	type alias TransactionOrder
	if err := cbor.UnmarshalTaggedValue(TransactionOrderTag, data, (*alias)(t)); err != nil {
		return err
	}
	return EnsureVersion(t, t.Version, 1)
}

func (t *TransactionOrder) AddStateUnlockCommitProof(unlockProof []byte) {
	t.StateUnlock = append([]byte{byte(StateUnlockExecute)}, unlockProof...)
}

func (t *TransactionOrder) AddStateUnlockRollbackProof(unlockProof []byte) {
	t.StateUnlock = append([]byte{byte(StateUnlockRollback)}, unlockProof...)
}

func (c *ClientMetadata) GetTimeout() uint64 {
	if c == nil {
		return 0
	}
	return c.Timeout
}

func (c *ClientMetadata) GetMaxFee() uint64 {
	if c == nil {
		return 0
	}
	return c.MaxTransactionFee
}

func (c *ClientMetadata) GetFeeCreditRecordID() []byte {
	if c == nil {
		return nil
	}
	return c.FeeCreditRecordID
}

func (c *ClientMetadata) GetReferenceNumber() []byte {
	if c == nil {
		return nil
	}
	return c.ReferenceNumber
}

func (s StateLock) IsValid() error {
	if len(s.ExecutionPredicate) == 0 {
		return errors.New("missing execution predicate")
	}
	if len(s.RollbackPredicate) == 0 {
		return errors.New("missing rollback predicate")
	}
	return nil
}
