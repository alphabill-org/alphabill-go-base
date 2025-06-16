package money

import (
	"testing"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	"github.com/stretchr/testify/require"
)

func Test_CBOR(t *testing.T) {
	unitData := &BillData{
		Version:        1,
		Value:          100,
		OwnerPredicate: []byte{0x01},
		Counter:        42,
	}
	newUnitData := &BillData{}

	unitDataBytes, err := cbor.Marshal(unitData)
	require.NoError(t, err)
	require.NoError(t, cbor.Unmarshal(unitDataBytes, newUnitData))
	require.Equal(t, unitData, newUnitData)
}
