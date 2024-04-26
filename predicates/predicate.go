package predicates

import "github.com/alphabill-org/alphabill-go-sdk/types"

type Predicate struct {
	_      struct{} `cbor:",toarray"`
	Tag    uint64
	Code   []byte
	Params []byte
}

func (p Predicate) AsBytes() (types.PredicateBytes, error) {
	buf, err := types.Cbor.Marshal(p)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
