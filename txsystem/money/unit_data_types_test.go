package money

import (
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/stretchr/testify/require"
)

func Test_CBOR(t *testing.T) {
	unitData := &BillData{
		Version:        1,
		Value:          100,
		OwnerPredicate: []byte{0x01},
		Locked:         0,
		Counter:        42,
	}
	newUnitData := &BillData{}

	unitDataBytes, err := types.Cbor.Marshal(unitData)
	require.NoError(t, err)
	require.NoError(t, types.Cbor.Unmarshal(unitDataBytes, newUnitData))
	require.Equal(t, unitData, newUnitData)
}
