package interface_uc_array_cbor_tags

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/stretchr/testify/require"
)

func Test_TransRec(t *testing.T) {
	tr := &TransactionRecord{
		Tx: &TransactionOrderV1{
			TypeID: 42,
		},
	}
	data, err := types.Cbor.Marshal(tr)
	require.NoError(t, err)

	fmt.Printf("Serialized CBOR: %X\n", data)

	tr2 := &TransactionRecord{}
	if err := types.Cbor.Unmarshal(data, tr2); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, tr, tr2)
	if !reflect.DeepEqual(tr, tr2) {
		t.Fatalf("expected %v, got %v", tr, tr2)
	}
}
