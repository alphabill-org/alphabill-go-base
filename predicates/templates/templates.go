package templates

import (
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/hash"
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
	return NewP2pkh256FromKeyHash(hash.Sum256(pubKey))
}

func NewP2pkh256FromKeyHash(pubKeyHash []byte) predicates.Predicate {
	return predicates.Predicate{Tag: TemplateStartByte, Code: []byte{P2pkh256ID}, Params: pubKeyHash}
}

func NewP2pkh256BytesFromKey(pubKey []byte) types.PredicateBytes {
	pb, _ := types.Cbor.Marshal(NewP2pkh256FromKey(pubKey))
	return pb
}

func NewP2pkh256BytesFromKeyHash(pubKeyHash []byte) types.PredicateBytes {
	pb, _ := types.Cbor.Marshal(NewP2pkh256FromKeyHash(pubKeyHash))
	return pb
}

func NewP2pkh256SignatureBytes(sig, pubKey []byte) []byte {
	sb, _ := types.Cbor.Marshal(P2pkh256Signature{Sig: sig, PubKey: pubKey})
	return sb
}

func ExtractPubKeyHashFromP2pkhPredicate(pb []byte) ([]byte, error) {
	predicate := &predicates.Predicate{}
	if err := types.Cbor.Unmarshal(pb, predicate); err != nil {
		return nil, fmt.Errorf("extracting predicate: %w", err)
	}
	if predicate.Tag != TemplateStartByte {
		return nil, fmt.Errorf("not a predicate template (tag %d)", predicate.Tag)
	}
	if len(predicate.Code) != 1 && predicate.Code[0] != P2pkh256ID {
		return nil, fmt.Errorf("not a p2pkh predicate (id %X)", predicate.Code)
	}
	return predicate.Params, nil
}

func IsP2pkhTemplate(predicate *predicates.Predicate) bool {
	return predicate != nil && predicate.Tag == TemplateStartByte && len(predicate.Code) == 1 && predicate.Code[0] == P2pkh256ID
}
