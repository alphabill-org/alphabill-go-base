package types

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	networkID         NetworkID   = 1
	partitionID       PartitionID = 0x01000001
	transactionType   uint16      = 1
	unitID                        = make([]byte, 32)
	timeout           uint64      = 42
	maxFee            uint64      = 69
	feeCreditRecordID             = []byte{32, 32, 32, 32}
	newOwnerPredicate             = []byte{1, 2, 3, 4}
	targetValue       uint64      = 100
	counter           uint64      = 123

	// 88                                       # array(8)
	//   01                                     #   unsigned(1)
	//   1A                                     #   uint32
	//      01000001                            #     "\x01\x00\x00\x01"
	//   58 20                                  #   bytes(32)
	//      00000000000000000000000000000000    #     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	//      00000000000000000000000000000000    #     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	//   01                                     #   unsigned(1)
	//   83                                     #   array(3)
	//      44                                  #     bytes(4)
	//         01020304                         #       "\x01\x02\x03\x04"
	//      18 64                               #     unsigned(100)
	//      58 20                               #     bytes(32)
	//         00000000000000000000000000000000 #       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	//         00000000000000000000000000000000 #       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	//   F6                                     #   primitive(22)
	//   84                                     #   array(4)
	//      18 2a                               #     unsigned(42)
	//      18 45                               #     unsigned(69)
	//      44                                  #     bytes(4)
	//         20202020                         #       "    "
	//      43                                  #     bytes(3)
	//         524546                           #       "REF"
	//   F6                                     #   primitive(22)
	payloadInHEX = "87" + // 8 element array
		"01" + // NetworkID
		"1A01000001" + // PartitionID
		"58200000000000000000000000000000000000000000000000000000000000000000" + // UnitID
		"01" + // Type
		"8344010203041864187b" + // Attributes
		"f6" + // State lock
		"84182a1845442020202043524546" // Client metadata
)

type testAttributes struct {
	_                 struct{} `cbor:",toarray"`
	NewOwnerPredicate []byte
	TargetValue       uint64
	Counter           uint64
}

func TestMarshalPayload(t *testing.T) {
	payload := createTransactionOrder(t).Payload
	payloadBytes, err := Cbor.Marshal(payload)
	require.NoError(t, err)
	require.Equal(t, hexDecode(t, payloadInHEX), payloadBytes)
}

func TestMarshalNilValuesInPayload(t *testing.T) {
	txo := &TransactionOrder{
		Payload: Payload{
			NetworkID:      0,
			PartitionID:    0,
			UnitID:         nil,
			Type:           0,
			Attributes:     nil,
			StateLock:      nil,
			ClientMetadata: nil,
		},
	}
	payloadBytes, err := Cbor.Marshal(txo.Payload)
	require.NoError(t, err)
	// 87    # array(7)
	//   00 #   zero, unsigned int
	//   00 #   zero, unsigned int
	//   f6 #   null, simple(22)
	//   00 #   zero, unsigned int
	//   f6 #   null, simple(22)
	//   f6 #   null, simple(22)
	//   f6 #   null, simple(22)
	require.Equal(t, []byte{0x87, 0x0, 0x0, 0xf6, 0x0, 0xf6, 0xf6, 0xf6}, payloadBytes)

	var payload Payload
	require.NoError(t, Cbor.Unmarshal(payloadBytes, &payload))
	require.EqualValues(t, txo.Payload, payload)
}

func TestUnmarshalPayload(t *testing.T) {
	var payload Payload
	require.NoError(t, Cbor.Unmarshal(hexDecode(t, payloadInHEX), &payload))
	require.Equal(t, networkID, payload.NetworkID)
	require.Equal(t, partitionID, payload.PartitionID)
	require.Equal(t, UnitID(unitID), payload.UnitID)
	require.Equal(t, transactionType, payload.Type)

	txo := TransactionOrder{Payload: payload}
	var attributes *testAttributes
	require.NoError(t, txo.UnmarshalAttributes(&attributes))
	require.Equal(t, newOwnerPredicate, attributes.NewOwnerPredicate)
	require.Equal(t, targetValue, attributes.TargetValue)
	require.Equal(t, counter, attributes.Counter)

	clientMetadata := payload.ClientMetadata
	require.NotNil(t, clientMetadata)
	require.Equal(t, timeout, clientMetadata.Timeout)
	require.Equal(t, maxFee, clientMetadata.MaxTransactionFee)
	require.Equal(t, feeCreditRecordID, clientMetadata.FeeCreditRecordID)
}

func TestUnmarshalAttributes(t *testing.T) {
	txo := createTransactionOrder(t)
	attr := &testAttributes{}
	require.NoError(t, txo.UnmarshalAttributes(attr))
	require.Equal(t, newOwnerPredicate, attr.NewOwnerPredicate)
	require.Equal(t, targetValue, attr.TargetValue)
	require.Equal(t, counter, attr.Counter)
	require.Equal(t, UnitID(unitID), txo.UnitID)
	require.Equal(t, partitionID, txo.PartitionID)
	require.Equal(t, timeout, txo.Timeout())
	require.Equal(t, transactionType, txo.Type)
	require.Equal(t, feeCreditRecordID, txo.FeeCreditRecordID())
	require.Equal(t, maxFee, txo.MaxFee())
	require.NotNil(t, txo.Hash(crypto.SHA256))
}

func TestHasStateLock(t *testing.T) {
	var txo *TransactionOrder
	require.False(t, txo.HasStateLock())

	txo = &TransactionOrder{}
	require.False(t, txo.HasStateLock())

	txo.StateLock = &StateLock{}
	require.True(t, txo.HasStateLock())
}

func Test_Payload_SetAttributes(t *testing.T) {
	expectedAttributes := &testAttributes{NewOwnerPredicate: []byte{9, 3, 5, 2, 6}, TargetValue: 59, Counter: 123}
	txo := TransactionOrder{}
	require.NoError(t, txo.SetAttributes(expectedAttributes))

	actualAttributes := &testAttributes{}
	require.NoError(t, txo.UnmarshalAttributes(actualAttributes))
	require.Equal(t, expectedAttributes, actualAttributes, "expected to get back the same attributes")
}

func TestStateLock_IsValid(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := StateLock{
			ExecutionPredicate: []byte{1, 2, 3},
			RollbackPredicate:  []byte{2, 3, 5},
		}
		require.NoError(t, s.IsValid())
	})
	t.Run("err - execute is nil", func(t *testing.T) {
		s := StateLock{
			RollbackPredicate: []byte{2, 3, 5},
		}
		require.EqualError(t, s.IsValid(), "missing execution predicate")
	})
	t.Run("err - execute is nil", func(t *testing.T) {
		s := StateLock{
			ExecutionPredicate: []byte{2, 3, 5},
		}
		require.EqualError(t, s.IsValid(), "missing rollback predicate")
	})
}

func createTransactionOrder(t *testing.T) *TransactionOrder {
	attr := &testAttributes{NewOwnerPredicate: newOwnerPredicate, TargetValue: targetValue, Counter: counter}
	attrBytes, err := Cbor.Marshal(attr)
	require.NoError(t, err)
	return &TransactionOrder{Payload: Payload{
		NetworkID:   1,
		PartitionID: partitionID,
		UnitID:      unitID,
		Type:        transactionType,
		Attributes:  attrBytes,
		ClientMetadata: &ClientMetadata{
			Timeout:           timeout,
			MaxTransactionFee: maxFee,
			FeeCreditRecordID: feeCreditRecordID,
			ReferenceNumber:   []byte("REF"),
		},
	}}
}

func hexDecode(t *testing.T, s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		require.NoError(t, err)
	}
	return data
}
