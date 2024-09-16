package interface_uc_named_cbor

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type (
	Block struct {
		_  struct{} `cbor:",toarray"`
		ID string
		UC UnicityCertificate
	}
)

func (b *Block) MarshalCBOR() ([]byte, error) {
	var taggedUC cbor.Tag

	taggedUC = cbor.Tag{
		Number:  uint64(b.UC.GetVersion()),
		Content: b.UC,
	}

	// encode Block with self-describing Tag
	type Alias Block
	return cbor.Marshal(cbor.Tag{
		Number: uint64(Block1Tag),
		Content: &struct {
			_  struct{} `cbor:",toarray"`
			UC cbor.Tag
			*Alias
		}{
			UC:    taggedUC,
			Alias: (*Alias)(b),
		},
	})
}

func (b *Block) UnmarshalCBOR(data []byte) error {
	type Alias Block
	aux := &struct {
		_  struct{} `cbor:",toarray"`
		UC cbor.Tag
		*Alias
	}{
		Alias: (*Alias)(b),
	}

	if err := cbor.Unmarshal(data, aux); err != nil {
		return err
	}

	switch ABTag(aux.UC.Number) {
	case UC1Tag:
		var uc UnicityCertificateV1
		encodedData, _ := cbor.Marshal(aux.UC.Content)
		if err := cbor.Unmarshal(encodedData, &uc); err != nil {
			return err
		}
		b.UC = uc
	case UC2Tag:
		var uc UnicityCertificateV2
		encodedData, _ := cbor.Marshal(aux.UC.Content)
		if err := cbor.Unmarshal(encodedData, &uc); err != nil {
			return err
		}
		b.UC = uc
	default:
		return fmt.Errorf("unknown UnicityCertificate version: %d", aux.UC.Number)
	}

	return nil
}
