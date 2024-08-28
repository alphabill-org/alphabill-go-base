package tokens

import (
	"crypto"

	"github.com/alphabill-org/alphabill-go-base/types"
)

// HashForNewTokenID generates new token identifier from the transaction attributes and client metadata.
func HashForNewTokenID(tx *types.TransactionOrder, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	hasher.Write(tx.Payload.Attributes)
	tx.Payload.ClientMetadata.AddToHasher(hasher)
	return hasher.Sum(nil), nil
}
