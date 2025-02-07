package orchestration

import (
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/stretchr/testify/require"
)

func Test_CBOR(t *testing.T) {
	unitData := &VarData{
		Version:     1,
		EpochNumber: 42,
	}
	newUnitData := &VarData{}

	unitDataBytes, err := types.Cbor.Marshal(unitData)
	require.NoError(t, err)
	tag, _, err := types.Cbor.UnmarshalTagged(unitDataBytes)
	require.NoError(t, err)
	require.Equal(t, types.UnitDataTag, tag)
	require.NoError(t, types.Cbor.Unmarshal(unitDataBytes, newUnitData))
	require.Equal(t, unitData, newUnitData)
}
