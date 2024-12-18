package tokens

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alphabill-org/alphabill-go-base/types"
)

func Test_GenerateUnitID(t *testing.T) {
	pdr := types.PartitionDescriptionRecord{
		PartitionTypeID: 2,
		NetworkID:       400,
		PartitionID:     500,
		UnitIDLen:       256,
		TypeIDLen:       8,
	}

	validTXO := func() types.TransactionOrder {
		return types.TransactionOrder{
			Payload: types.Payload{
				NetworkID:   pdr.NetworkID,
				PartitionID: pdr.PartitionID,
				Type:        TransactionTypeMintFT,
			},
		}
	}

	t.Run("invalid networkID", func(t *testing.T) {
		txo := validTXO()
		txo.NetworkID++
		err := GenerateUnitID(&txo, types.ShardID{}, &pdr)
		require.EqualError(t, err, `invalid network 401 (expected 400)`)
	})

	t.Run("invalid partitionID", func(t *testing.T) {
		txo := validTXO()
		txo.PartitionID++
		err := GenerateUnitID(&txo, types.ShardID{}, &pdr)
		require.EqualError(t, err, `invalid partition 501 (expected 500)`)
	})

	t.Run("invalid shard", func(t *testing.T) {
		txo := validTXO()
		id0, _ := types.ShardID{}.Split()
		err := GenerateUnitID(&txo, id0, &pdr)
		require.EqualError(t, err, `invalid shard ID: only empty shard ID is valid in a single-shard sharding scheme`)
	})

	t.Run("invalid tx type", func(t *testing.T) {
		// only "mint" transactions (ie those creating unit) are allowed
		txo := validTXO()
		for _, txt := range []uint16{TransactionTypeTransferFT, TransactionTypeTransferNFT, TransactionTypeLockToken, TransactionTypeUnlockToken, TransactionTypeSplitFT, TransactionTypeBurnFT, TransactionTypeJoinFT, TransactionTypeUpdateNFT} {
			txo.Type = txt
			err := GenerateUnitID(&txo, types.ShardID{}, &pdr)
			require.EqualError(t, err, fmt.Sprintf(`invalid tx type %#x - unit ID can be generated only for "mint" transactions`, txt))
		}
	})

	t.Run("success", func(t *testing.T) {
		txo := validTXO()
		for _, txt := range []uint16{TransactionTypeDefineFT, TransactionTypeDefineNFT, TransactionTypeMintFT, TransactionTypeMintNFT} {
			txo.Type = txt
			txo.UnitID = nil

			require.NoError(t, GenerateUnitID(&txo, types.ShardID{}, &pdr))
			require.Len(t, txo.UnitID, (int(pdr.UnitIDLen+pdr.TypeIDLen) / 8))

			tid, err := pdr.ExtractUnitType(txo.UnitID)
			require.NoError(t, err)
			require.EqualValues(t, txt, tid)
		}
	})
}
