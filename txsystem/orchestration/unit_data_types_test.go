package orchestration

import (
	"testing"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	"github.com/stretchr/testify/require"
)

func Test_CBOR(t *testing.T) {
	unitData := &VarData{
		Version:     1,
		EpochNumber: 42,
	}
	newUnitData := &VarData{}

	unitDataBytes, err := cbor.Marshal(unitData)
	require.NoError(t, err)
	require.NoError(t, cbor.Unmarshal(unitDataBytes, newUnitData))
	require.Equal(t, unitData, newUnitData)
}
