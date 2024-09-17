package interface_uc_named_cbor

import (
	"fmt"
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestCborArray_uc1(t *testing.T) {
	block := &Block{
		ID: "block-1",
		UC: &UnicityCertificateV1{FieldA: "test-fieldA"},
	}

	cborData, err := types.Cbor.Marshal(block)
	if err != nil {
		fmt.Println("Error serializing block:", err)
		return
	}

	fmt.Printf("Serialized CBOR: %X\n", cborData)

	var taggedBlock cbor.Tag
	err = types.Cbor.Unmarshal(cborData, &taggedBlock)
	require.NoError(t, err)
	require.EqualValues(t, Block1Tag, taggedBlock.Number)

	var newBlock Block
	err = types.Cbor.Unmarshal(cborData, &newBlock)
	require.NoError(t, err)

	fmt.Printf("Deserialized Block: %+v\n", newBlock)

	require.Equal(t, block, &newBlock)
}

func TestCborArray_uc2(t *testing.T) {
	block := &Block{
		ID: "block-2",
		H:  &Header{S: "header-2"},
		UC: &UnicityCertificateV2{FieldB: 42},
	}

	cborData, err := types.Cbor.Marshal(block)
	if err != nil {
		fmt.Println("Error serializing block:", err)
		return
	}

	fmt.Printf("Serialized CBOR: %X\n", cborData)

	var newBlock Block
	if err := types.Cbor.Unmarshal(cborData, &newBlock); err != nil {
		fmt.Println("Error deserializing block:", err)
		return
	}

	fmt.Printf("Deserialized Block: %+v\n", newBlock)

	require.Equal(t, block, &newBlock)
}
