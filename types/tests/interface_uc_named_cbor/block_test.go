package interface_uc_named_cbor

import (
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

type (
	UnicityCertificate interface {
		Validate() error
	}

	UnicityCertificateV1 struct {
		FieldA string
	}

	UnicityCertificateV2 struct {
		FieldB int
	}

	Block struct {
		ID string             `cbor:"id"`
		UC UnicityCertificate `cbor:"uc"`
	}

	VersionedUC struct {
		Version string      `cbor:"version"`
		Data    interface{} `cbor:"data"`
	}
)

func (uc UnicityCertificateV1) Validate() error {
	return nil
}

func (uc UnicityCertificateV2) Validate() error {
	return nil
}

func (b *Block) MarshalCBOR() ([]byte, error) {
	var versionedUC VersionedUC

	switch uc := b.UC.(type) {
	case UnicityCertificateV1:
		versionedUC = VersionedUC{
			Version: "UnicityCertificateV1",
			Data:    uc,
		}
	case UnicityCertificateV2:
		versionedUC = VersionedUC{
			Version: "UnicityCertificateV2",
			Data:    uc,
		}
	default:
		return nil, fmt.Errorf("unknown UnicityCertificate type")
	}

	type Alias Block
	return cbor.Marshal(&struct {
		UC VersionedUC `cbor:"uc"`
		*Alias
	}{
		UC:    versionedUC,
		Alias: (*Alias)(b),
	})
}

func (b *Block) UnmarshalCBOR(data []byte) error {
	type Alias Block
	aux := &struct {
		UC VersionedUC `cbor:"uc"`
		*Alias
	}{
		Alias: (*Alias)(b),
	}

	if err := cbor.Unmarshal(data, aux); err != nil {
		return err
	}

	switch aux.UC.Version {
	case "UnicityCertificateV1":
		var uc UnicityCertificateV1
		encodedData, _ := cbor.Marshal(aux.UC.Data)
		if err := cbor.Unmarshal(encodedData, &uc); err != nil {
			return err
		}
		b.UC = uc
	case "UnicityCertificateV2":
		var uc UnicityCertificateV2
		encodedData, _ := cbor.Marshal(aux.UC.Data)
		if err := cbor.Unmarshal(encodedData, &uc); err != nil {
			return err
		}
		b.UC = uc
	default:
		return fmt.Errorf("unknown UnicityCertificate version: %s", aux.UC.Version)
	}

	return nil
}

func Test2(t *testing.T) {
	block := &Block{
		ID: "block-123",
		UC: UnicityCertificateV1{FieldA: "test-field"},
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
