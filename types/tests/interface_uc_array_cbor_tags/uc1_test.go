package interface_uc_array_cbor_tags

import (
	"fmt"
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/stretchr/testify/require"
)

func Test_uc1(t *testing.T) {
	uc := &UnicityCertificateV1{
		FieldA: "fieldA",
	}
	data, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)

	fmt.Printf("Serialized CBOR: %X\n", data)

	ucInterface, err := decodeUnicityCertificate(data)
	require.NoError(t, err)
	require.Equal(t, uc, ucInterface)

	var uc2 UnicityCertificateV1
	if err := types.Cbor.Unmarshal(data, &uc2); err != nil {
		t.Fatal(err)
	}
	if uc2.FieldA != uc.FieldA {
		t.Fatalf("expected %v, got %v", uc.FieldA, uc2.FieldA)
	}
	require.Equal(t, uc, &uc2)
}
