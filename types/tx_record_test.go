package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alphabill-org/alphabill-go-base/cbor"
)

type testProcessingDetails struct {
	_ struct{} `cbor:",toarray"`
	A int
	B string
}

func TestTransactionRecordFunctions(t *testing.T) {
	txo := createTransactionOrder(t)
	expectedProcessingDetails := testProcessingDetails{A: 97, B: "b"}
	processingDetailsCBOR, err := cbor.Marshal(expectedProcessingDetails)
	require.NoError(t, err)

	txr := createTransactionRecord(t, txo, 1)
	txr.ServerMetadata.ProcessingDetails = processingDetailsCBOR

	t.Run("Test Hash", func(t *testing.T) {
		require.NotEmpty(t, doHash(t, txr))
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

	t.Run("Test Unmarshal", func(t *testing.T) {
		txrBytes, err := txr.MarshalCBOR()
		require.NoError(t, err)

		txr2 := &TransactionRecord{}
		require.NoError(t, txr2.UnmarshalCBOR(txrBytes))
		require.Equal(t, txr, txr2)
		require.NoError(t, txr2.IsValid())
	})

	t.Run("Test Unmarshal invalid version", func(t *testing.T) {
		txr.Version = 2
		txrBytes, err := txr.MarshalCBOR()
		require.NoError(t, err)

		txr2 := &TransactionRecord{}
		require.ErrorContains(t, txr2.UnmarshalCBOR(txrBytes), "invalid version (type *types.TransactionRecord), expected 1, got 2")
	})
}

func createTransactionRecord(t *testing.T, tx *TransactionOrder, fee uint64) *TransactionRecord {
	txoBytes, err := tx.MarshalCBOR()
	require.NoError(t, err)
	return &TransactionRecord{
		Version:          1,
		TransactionOrder: txoBytes,
		ServerMetadata: &ServerMetadata{
			ActualFee:        fee,
			TargetUnits:      []UnitID{tx.UnitID},
			SuccessIndicator: TxStatusSuccessful,
		},
	}
}
