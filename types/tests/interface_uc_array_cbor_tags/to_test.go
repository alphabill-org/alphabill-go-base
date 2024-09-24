package interface_uc_array_cbor_tags

import (
	"fmt"
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/stretchr/testify/require"
)

func Test_Txo(t *testing.T) {
	txo := &TransactionOrderV1{
		TypeID: 42,
	}
	data, err := types.Cbor.Marshal(txo)
	require.NoError(t, err)

	fmt.Printf("Serialized CBOR: %X\n", data)

	var txo2 TransactionOrderV1
	if err := types.Cbor.Unmarshal(data, &txo2); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, txo, &txo2)
}
