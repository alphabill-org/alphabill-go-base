package interface_uc_named_cbor

import (
	"fmt"
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

type (
	UnicityCertificate interface {
		Validate() error
	}

	UnicityCertificateV1 struct {
		_      struct{} `cbor:",toarray"`
		FieldA string
	}

	UnicityCertificateV2 struct {
		_      struct{} `cbor:",toarray"`
		FieldB int
	}

	Block struct {
		_  struct{} `cbor:",toarray"`
		ID string
		UC UnicityCertificate
	}

	VersionedUC struct {
		_       struct{} `cbor:",toarray"`
		Version types.Version
		Data    interface{}
	}
)

func (b *Block) MarshalCBOR() ([]byte, error) {
	var versionedUC VersionedUC

	switch uc := b.UC.(type) {
	case UnicityCertificateV1:
		versionedUC = VersionedUC{
			Version: 1,
			Data:    uc,
		}
	case UnicityCertificateV2:
		versionedUC = VersionedUC{
			Version: 2,
			Data:    uc,
		}
	default:
		return nil, fmt.Errorf("unknown UnicityCertificate type")
	}

	type Alias Block
	return cbor.Marshal(&struct {
		_  struct{} `cbor:",toarray"`
		UC VersionedUC
		*Alias
	}{
		UC:    versionedUC,
		Alias: (*Alias)(b),
	})
}

func (b *Block) UnmarshalCBOR(data []byte) error {
	type Alias Block
	aux := &struct {
		_  struct{} `cbor:",toarray"`
		UC VersionedUC
		*Alias
	}{
		Alias: (*Alias)(b),
	}

	if err := cbor.Unmarshal(data, aux); err != nil {
		return err
	}

	switch aux.UC.Version {
	case 1:
		var uc UnicityCertificateV1
		encodedData, _ := cbor.Marshal(aux.UC.Data)
		if err := cbor.Unmarshal(encodedData, &uc); err != nil {
			return err
		}
		b.UC = uc
	case 2:
		var uc UnicityCertificateV2
		encodedData, _ := cbor.Marshal(aux.UC.Data)
		if err := cbor.Unmarshal(encodedData, &uc); err != nil {
			return err
		}
		b.UC = uc
	default:
		return fmt.Errorf("unknown UnicityCertificate version: %d", aux.UC.Version)
	}

	return nil
}

func (uc UnicityCertificateV1) Validate() error {
	return nil
}

func (uc UnicityCertificateV2) Validate() error {
	return nil
}

func TestCborArray_uc1(t *testing.T) {
	block := &Block{
		ID: "block-1",
		UC: UnicityCertificateV1{FieldA: "test-fieldA"},
	}

	cborData, err := cbor.Marshal(block)
	if err != nil {
		fmt.Println("Error serializing block:", err)
		return
	}

	fmt.Printf("Serialized CBOR: %X\n", cborData)

	var newBlock Block
	if err := cbor.Unmarshal(cborData, &newBlock); err != nil {
		fmt.Println("Error deserializing block:", err)
		return
	}

	fmt.Printf("Deserialized Block: %+v\n", newBlock)

	require.Equal(t, block, &newBlock)
}

func TestCborArray_uc2(t *testing.T) {
	block := &Block{
		ID: "block-2",
		UC: UnicityCertificateV2{FieldB: 42},
	}

	cborData, err := cbor.Marshal(block)
	if err != nil {
		fmt.Println("Error serializing block:", err)
		return
	}

	fmt.Printf("Serialized CBOR: %X\n", cborData)

	var newBlock Block
	if err := cbor.Unmarshal(cborData, &newBlock); err != nil {
		fmt.Println("Error deserializing block:", err)
		return
	}

	fmt.Printf("Deserialized Block: %+v\n", newBlock)

	require.Equal(t, block, &newBlock)
}
