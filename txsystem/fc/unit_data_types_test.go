package fc

import (
	"testing"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"

	"github.com/stretchr/testify/require"
)

func TestFCR_HashIsCalculatedCorrectly(t *testing.T) {
	fcr := &FeeCreditRecord{
		Version:        1,
		Balance:        1,
		OwnerPredicate: []byte{1, 2, 3},
		Counter:        10,
		MinLifetime:    2,
	}
	// calculate actual hash
	hasher := abhash.NewSha256()
	fcr.Write(hasher)
	actualHash, err := hasher.Sum()
	require.NoError(t, err)

	// calculate expected hash
	hasher.Reset()
	res, err := cbor.Marshal(fcr)
	require.NoError(t, err)
	hasher.WriteRaw(res)
	expectedHash, err := hasher.Sum()
	require.NoError(t, err)
	require.Equal(t, expectedHash, actualHash)

	// check all fields serialized
	var fcrFromSerialized FeeCreditRecord
	require.NoError(t, cbor.Unmarshal(res, &fcrFromSerialized))
	require.Equal(t, fcr, &fcrFromSerialized)
}

func TestFCR_SummaryValueIsZero(t *testing.T) {
	fcr := &FeeCreditRecord{
		Balance:     1,
		Counter:     10,
		MinLifetime: 2,
	}
	require.Equal(t, uint64(0), fcr.SummaryValueInput())
}

func Test_CBOR(t *testing.T) {
	unitData := &FeeCreditRecord{
		Version:        1,
		Balance:        42,
		MinLifetime:    100,
		OwnerPredicate: []byte{0x01},
		Counter:        42,
	}
	newUnitData := &FeeCreditRecord{}

	unitDataBytes, err := cbor.Marshal(unitData)
	require.NoError(t, err)
	require.NoError(t, cbor.Unmarshal(unitDataBytes, newUnitData))
	require.Equal(t, unitData, newUnitData)
}
