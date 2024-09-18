package interface_uc_array_cbor_tags

import (
	"fmt"
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/stretchr/testify/require"
)

func Test_uc2(t *testing.T) {
	uc := &UnicityCertificateV2{
		FieldB: 42,
	}
	data, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)

	fmt.Printf("Serialized CBOR: %X\n", data)

	ucInterface, err := decodeUnicityCertificate(data)
	require.NoError(t, err)
	require.Equal(t, uc, ucInterface)

	var uc2 UnicityCertificateV2
	if err := types.Cbor.Unmarshal(data, &uc2); err != nil {
		t.Fatal(err)
	}
	if uc2.FieldB != uc.FieldB {
		t.Fatalf("expected %v, got %v", uc.FieldB, uc2.FieldB)
	}
	require.Equal(t, uc, &uc2)
}
