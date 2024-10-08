package types

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
)

type testProcessingDetails struct {
	_ struct{} `cbor:",toarray"`
	A int
	B string
}

func TestTransactionRecordFunctions(t *testing.T) {
	txo := createTransactionOrder(t)
	expectedProcessingDetails := testProcessingDetails{A: 97, B: "b"}
	processingDetailsCBOR, err := Cbor.Marshal(expectedProcessingDetails)
	require.NoError(t, err)
	serverMetadata := &ServerMetadata{
		ActualFee:         1,
		TargetUnits:       []UnitID{txo.UnitID},
		SuccessIndicator:  TxStatusSuccessful,
		ProcessingDetails: processingDetailsCBOR,
	}
	txr := &TransactionRecord{
		TransactionOrder: txo,
		ServerMetadata:   serverMetadata,
	}

	t.Run("Test Hash", func(t *testing.T) {
		require.NotEmpty(t, txr.Hash(crypto.SHA256))
	})

	t.Run("Test Bytes", func(t *testing.T) {
		bytes, err := txr.Bytes()
		require.NoError(t, err)
		require.NotEmpty(t, bytes)
	})

	t.Run("Test UnmarshalProcessingDetails", func(t *testing.T) {
		var actualProcessingDetails testProcessingDetails
		require.NoError(t, txr.UnmarshalProcessingDetails(&actualProcessingDetails))
		require.Equal(t, expectedProcessingDetails, actualProcessingDetails)
	})

	t.Run("Test GetActualFee", func(t *testing.T) {
		require.EqualValues(t, uint64(1), txr.GetActualFee())
	})
}

func createTransactionRecord(tx *TransactionOrder, fee uint64) *TransactionRecord {
	return &TransactionRecord{
		TransactionOrder: tx,
		ServerMetadata: &ServerMetadata{
			ActualFee:        fee,
			SuccessIndicator: TxStatusSuccessful,
		},
	}
}
