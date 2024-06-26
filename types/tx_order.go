package types

import (
	"crypto"
	"errors"
	"fmt"
	"hash"

	"github.com/alphabill-org/alphabill-go-base/util"
)

type (
	TransactionOrder struct {
		_           struct{} `cbor:",toarray"`
		Payload     *Payload
		OwnerProof  []byte
		FeeProof    []byte
		StateUnlock []byte // two CBOR data items: [0|1]+[<state lock/rollback predicate input>]
	}

	Payload struct {
		_              struct{} `cbor:",toarray"`
		SystemID       SystemID
		Type           string
		UnitID         UnitID
		Attributes     RawCBOR
		StateLock      *StateLock
		ClientMetadata *ClientMetadata
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

	PredicateBytes = Bytes

	ProofGenerator func(bytesToSign []byte) (proof []byte, err error)

	SigBytesProvider interface {
		SigBytes() ([]byte, error)
	}
)

func (s StateLock) IsValid() error {
	if len(s.ExecutionPredicate) == 0 {
		return errors.New("missing execution predicate")
	}
	if len(s.RollbackPredicate) == 0 {
		return errors.New("missing rollback predicate")
	}
	return nil
}

func (t *TransactionOrder) PayloadBytes() ([]byte, error) {
	return t.Payload.Bytes()
}

func (t *TransactionOrder) UnmarshalAttributes(v any) error {
	if t == nil {
		return errors.New("transaction order is nil")
	}
	return t.Payload.UnmarshalAttributes(v)
}

func (t *TransactionOrder) UnitID() UnitID {
	if t.Payload == nil {
		return nil
	}
	return t.Payload.UnitID
}

func (t *TransactionOrder) SystemID() SystemID {
	if t.Payload == nil {
		return 0
	}
	return t.Payload.SystemID
}

func (t *TransactionOrder) Timeout() uint64 {
	if t.Payload == nil || t.Payload.ClientMetadata == nil {
		return 0
	}
	return t.Payload.ClientMetadata.Timeout
}

func (t *TransactionOrder) PayloadType() string {
	if t.Payload == nil {
		return ""
	}
	return t.Payload.Type
}

func (t *TransactionOrder) GetClientFeeCreditRecordID() []byte {
	if t.Payload == nil || t.Payload.ClientMetadata == nil {
		return nil
	}
	return t.Payload.ClientMetadata.FeeCreditRecordID
}

func (t *TransactionOrder) GetClientMaxTxFee() uint64 {
	if t.Payload == nil || t.Payload.ClientMetadata == nil {
		return 0
	}
	return t.Payload.ClientMetadata.MaxTransactionFee
}

func (t *TransactionOrder) Hash(algorithm crypto.Hash) []byte {
	hasher := algorithm.New()
	b, err := Cbor.Marshal(t)
	if err != nil {
		//TODO
		panic(err)
	}
	hasher.Write(b)
	return hasher.Sum(nil)
}

/*
SetOwnerProof assigns the bytes returned by the function provided as argument to
the OwnerProof field unless the function (or reading data to be signed by that
function) returned error.
*/
func (t *TransactionOrder) SetOwnerProof(proofer ProofGenerator) error {
	data, err := t.PayloadBytes()
	if err != nil {
		return fmt.Errorf("reading payload bytes to sign: %w", err)
	}
	if t.OwnerProof, err = proofer(data); err != nil {
		return fmt.Errorf("generating owner proof: %w", err)
	}
	return nil
}

// HashForNewUnitID generates hash for new unit identifier calculation.
func (t *TransactionOrder) HashForNewUnitID(hashFunc crypto.Hash, extra ...[]byte) []byte {
	hasher := hashFunc.New()
	hasher.Write(t.UnitID())
	hasher.Write(t.Payload.Attributes)
	t.Payload.ClientMetadata.AddToHasher(hasher)
	for _, e := range extra {
		hasher.Write(e)
	}
	return hasher.Sum(nil)
}

/*
SetAttributes serializes "attr" and assigns the result to payload's Attributes field.
The "attr" is expected to be one of the transaction attribute structs but there is
no validation!
The Payload.UnmarshalAttributes can be used to decode the attributes.
*/
func (p *Payload) SetAttributes(attr any) error {
	bytes, err := Cbor.Marshal(attr)
	if err != nil {
		return fmt.Errorf("marshaling %T as tx attributes: %w", attr, err)
	}
	p.Attributes = bytes
	return nil
}

func (p *Payload) UnmarshalAttributes(v any) error {
	if p == nil {
		return errors.New("payload is nil")
	}
	return Cbor.Unmarshal(p.Attributes, v)
}

func (p *Payload) HasStateLock() bool {
	return p != nil && p.StateLock != nil
}

func (p *Payload) Bytes() ([]byte, error) {
	return Cbor.Marshal(p)
}

// BytesWithAttributeSigBytes TODO: AB-1016 remove this hack
func (p *Payload) BytesWithAttributeSigBytes(attrs SigBytesProvider) ([]byte, error) {
	attrBytes, err := attrs.SigBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attributes: %w", err)
	}
	payload := &Payload{
		SystemID:       p.SystemID,
		Type:           p.Type,
		UnitID:         p.UnitID,
		Attributes:     attrBytes,
		ClientMetadata: p.ClientMetadata,
	}
	return payload.Bytes()
}

func (c *ClientMetadata) AddToHasher(hasher hash.Hash) {
	hasher.Write(util.Uint64ToBytes(c.Timeout))
	hasher.Write(util.Uint64ToBytes(c.MaxTransactionFee))
	hasher.Write(c.FeeCreditRecordID)
	hasher.Write(c.ReferenceNumber)
}
