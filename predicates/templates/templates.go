package templates

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	"github.com/alphabill-org/alphabill-go-base/predicates"
	"github.com/alphabill-org/alphabill-go-base/types"
)

const (
	AlwaysFalseID byte = iota
	AlwaysTrueID
	P2pkh256ID

	TemplateStartByte = 0x00
)

var (
	alwaysFalseBytes = []byte{0x83, 0x00, 0x41, 0x00, 0xf6}
	alwaysTrueBytes  = []byte{0x83, 0x00, 0x41, 0x01, 0xf6}

	cborNull = []byte{0xf6}
)

type (
	/*
	   P2pkh256Signature is a signature and public key pair, typically used as
	   owner proof (ie the public key can be used to verify the signature).
	*/
	P2pkh256Signature struct {
		_      struct{} `cbor:",toarray"`
		Sig    []byte
		PubKey []byte
	}
)

func AlwaysFalseBytes() types.PredicateBytes {
	return alwaysFalseBytes
}

func AlwaysTrueBytes() types.PredicateBytes {
	return alwaysTrueBytes
}

func EmptyArgument() []byte {
	return cborNull
}

func NewP2pkh256FromKey(pubKey []byte) predicates.Predicate {
	pkh := sha256.Sum256(pubKey)
	return NewP2pkh256FromKeyHash(pkh[:])
}

func NewP2pkh256FromKeyHash(pubKeyHash []byte) predicates.Predicate {
	return predicates.Predicate{Tag: TemplateStartByte, Code: []byte{P2pkh256ID}, Params: pubKeyHash}
}

func NewP2pkh256BytesFromKey(pubKey []byte) types.PredicateBytes {
	pb, _ := cbor.Marshal(NewP2pkh256FromKey(pubKey))
	return pb
}

func NewP2pkh256BytesFromKeyHash(pubKeyHash []byte) types.PredicateBytes {
	pb, _ := cbor.Marshal(NewP2pkh256FromKeyHash(pubKeyHash))
	return pb
}

func NewP2pkh256SignatureBytes(sig, pubKey []byte) []byte {
	sb, _ := cbor.Marshal(P2pkh256Signature{Sig: sig, PubKey: pubKey})
	return sb
}

func ExtractPubKeyHashFromP2pkhPredicate(pb []byte) ([]byte, error) {
	predicate := &predicates.Predicate{}
	if err := cbor.Unmarshal(pb, predicate); err != nil {
		return nil, fmt.Errorf("extracting predicate: %w", err)
	}
	if err := VerifyP2pkhPredicate(predicate); err != nil {
		return nil, err
	}
	return predicate.Params, nil
}

// VerifyP2pkhPredicate returns nil if the predicate is a valid P2PKH256 predicate,
// or an error if the predicate is invalid, with a description of the specific validation error.
func VerifyP2pkhPredicate(predicate *predicates.Predicate) error {
	if predicate == nil {
		return errors.New("predicate is nil")
	}
	if predicate.Tag != TemplateStartByte {
		return fmt.Errorf("not a predicate template (tag %d)", predicate.Tag)
	}
	if len(predicate.Code) != 1 || predicate.Code[0] != P2pkh256ID {
		return fmt.Errorf("not a p2pkh predicate (id %X)", predicate.Code)
	}
	return nil
}
