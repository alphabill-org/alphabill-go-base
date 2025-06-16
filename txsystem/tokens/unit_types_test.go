package tokens

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alphabill-org/alphabill-go-base/cbor"
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
		err := GenerateUnitID(&txo, &pdr)
		require.EqualError(t, err, `invalid network 401 (expected 400)`)
	})

	t.Run("invalid partitionID", func(t *testing.T) {
		txo := validTXO()
		txo.PartitionID++
		err := GenerateUnitID(&txo, &pdr)
		require.EqualError(t, err, `invalid partition 501 (expected 500)`)
	})

	t.Run("invalid tx type", func(t *testing.T) {
		// only "mint" transactions (ie those creating unit) are allowed
		txo := validTXO()
		for _, txt := range []uint16{TransactionTypeTransferFT, TransactionTypeTransferNFT, TransactionTypeSplitFT, TransactionTypeBurnFT, TransactionTypeJoinFT, TransactionTypeUpdateNFT} {
			txo.Type = txt
			err := GenerateUnitID(&txo, &pdr)
			require.EqualError(t, err, fmt.Sprintf(`invalid tx type %#x - unit ID can be generated only for "mint" transactions`, txt))
		}
	})

	t.Run("success", func(t *testing.T) {
		txo := validTXO()
		for _, txt := range []uint16{TransactionTypeDefineFT, TransactionTypeDefineNFT, TransactionTypeMintFT, TransactionTypeMintNFT} {
			txo.Type = txt
			txo.UnitID = nil

			require.NoError(t, GenerateUnitID(&txo, &pdr))
			require.Len(t, txo.UnitID, (int(pdr.UnitIDLen+pdr.TypeIDLen) / 8))

			tid, err := pdr.ExtractUnitType(txo.UnitID)
			require.NoError(t, err)
			require.EqualValues(t, txt, tid)
		}
	})
}

func Test_CBOR(t *testing.T) {
	unitDatas := []types.UnitData{
		&NonFungibleTokenTypeData{
			Version:                  1,
			Symbol:                   "NFT",
			Name:                     "Non-Fungible Token",
			Icon:                     nil,
			ParentTypeID:             []byte{0x01, 0x02},
			SubTypeCreationPredicate: []byte{0x03, 0x04},
			TokenMintingPredicate:    []byte{0x05, 0x06},
			TokenTypeOwnerPredicate:  []byte{0x07, 0x08},
			DataUpdatePredicate:      []byte{0x09, 0x0A},
		},
		&FungibleTokenTypeData{
			Version:                  1,
			Symbol:                   "FT",
			Name:                     "Fungible Token",
			Icon:                     nil,
			ParentTypeID:             []byte{0x01, 0x02},
			DecimalPlaces:            18,
			SubTypeCreationPredicate: []byte{0x03, 0x04},
			TokenMintingPredicate:    []byte{0x05, 0x06},
			TokenTypeOwnerPredicate:  []byte{0x07, 0x08},
		},
		&NonFungibleTokenData{
			Version:             1,
			TypeID:              []byte{0x01, 0x02},
			Name:                "NFT Data",
			URI:                 "http://example.com",
			Data:                []byte{0x03, 0x04},
			OwnerPredicate:      []byte{0x05, 0x06},
			DataUpdatePredicate: []byte{0x07, 0x08},
			Counter:             42,
		},
		&FungibleTokenData{
			Version:        1,
			TypeID:         []byte{0x01, 0x02},
			Value:          1000,
			OwnerPredicate: []byte{0x03, 0x04},
			Counter:        42,
			MinLifetime:    100,
		},
	}

	for _, unitData := range unitDatas {
		t.Run(reflect.TypeOf(unitData).String(), func(t *testing.T) {
			newUnitData := reflect.New(reflect.TypeOf(unitData).Elem()).Interface().(types.UnitData)
			unitDataBytes, err := cbor.Marshal(unitData)
			require.NoError(t, err)
			require.NoError(t, cbor.Unmarshal(unitDataBytes, newUnitData))
			require.Equal(t, unitData, newUnitData)
		})
	}
}
