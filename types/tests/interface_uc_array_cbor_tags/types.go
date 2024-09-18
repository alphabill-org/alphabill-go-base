package interface_uc_array_cbor_tags

import (
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
)

type ABTag uint64

const (
	UC1Tag ABTag = 1001
	UC2Tag ABTag = 1002

	Block1Tag ABTag = 2001

	TXO1Tag ABTag = 3001
)

type (
	Versioned interface {
		GetVersion() ABTag
	}

	TransactionOrder interface {
		Versioned
		GetTypeID() uint8
	}
)

func decodeTransactionOrder(data []byte) (TransactionOrder, error) {
	var tag cbor.Tag
	if err := types.Cbor.Unmarshal(data, &tag); err != nil {
		return nil, err
	}

	switch ABTag(tag.Number) {
	case TXO1Tag:
		var to TransactionOrderV1
		if err := types.Cbor.Unmarshal(data, &to); err != nil {
			return nil, err
		}
		return &to, nil
	default:
		return nil, fmt.Errorf("unknown transaction order tag: %d", tag.Number)
	}
}
