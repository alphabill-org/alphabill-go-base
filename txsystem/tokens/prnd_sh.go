package tokens

import (
	"crypto"

	"github.com/alphabill-org/alphabill-go-base/types"
)

// HashForNewTokenID generates new token identifier from the transaction signature bytes (attributes without signatures)
// and client metadata, attributes should be serialized without signatures as signatures depend on the token id itself.
func HashForNewTokenID(attrProvider types.SigBytesProvider, clientMetadata *types.ClientMetadata, hashFunc crypto.Hash) ([]byte, error) {
	attrBytes, err := attrProvider.SigBytes()
	if err != nil {
		return nil, err
	}
	hasher := hashFunc.New()
	hasher.Write(attrBytes)
	clientMetadata.AddToHasher(hasher)
	return hasher.Sum(nil), nil
}
