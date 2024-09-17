package interface_uc_array_cbor_tags

import (
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
)

type (
	Block struct {
		_  struct{} `cbor:",toarray"`
		ID string
		H  *Header
		UC UnicityCertificate
	}

	Header struct {
		_ struct{} `cbor:",toarray"`
		S string
	}
)

func (b *Block) MarshalCBOR() ([]byte, error) {
	// encode Block with self-describing Tag
	ucBytes, err := types.Cbor.Marshal(b.UC)
	if err != nil {
		return nil, err
	}
	fmt.Printf("UC bytes: %X\n", ucBytes)
	type alias Block
	return types.Cbor.Marshal(cbor.Tag{
		Number: uint64(Block1Tag),
		Content: &struct {
			_ struct{} `cbor:",toarray"`
			*alias
			UC []byte
		}{
			alias: (*alias)(b),
			UC:    ucBytes,
		},
	})
}

func (b *Block) UnmarshalCBOR(data []byte) error {
	type alias Block
	aux := &struct {
		_ struct{} `cbor:",toarray"`
		*alias
		UC []byte
	}{
		alias: (*alias)(b),
	}

	if err := types.Cbor.Unmarshal(data, aux); err != nil {
		return err
	}

	var err error
	b.UC, err = decodeUnicityCertificate(aux.UC)

	return err
}
