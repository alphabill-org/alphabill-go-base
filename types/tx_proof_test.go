package types

import (
	"crypto"
	"testing"
	"time"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	testsig "github.com/alphabill-org/alphabill-go-base/testutils/sig"
	"github.com/stretchr/testify/require"
)

func TestTxProofFunctions(t *testing.T) {
	t.Run("Test NewTxProof OK", func(t *testing.T) {
		signer, _ := testsig.CreateSignerAndVerifier(t)
		block := createBlock(t, "test", signer)
		txrProof, err := NewTxRecordProof(block, 0, crypto.SHA256)
		require.NoError(t, err)
		txProof := txrProof.TxProof
		require.Equal(t, block.HeaderHash(crypto.SHA256), txProof.BlockHeaderHash)
		require.Len(t, txProof.Chain, 1)
		require.Equal(t, block.UnicityCertificate, txProof.UnicityCertificate)
		require.Len(t, block.Transactions, 2)
		require.Equal(t, block.Transactions[0], txrProof.TxRecord)
	})

	t.Run("Test NewTxProof nil block", func(t *testing.T) {
		proof, err := NewTxRecordProof(nil, 0, crypto.SHA256)
		require.Nil(t, proof)
		require.ErrorContains(t, err, "block is nil")
	})

	t.Run("Test NewTxProof empty block", func(t *testing.T) {
		proof, err := NewTxRecordProof(&Block{}, 0, crypto.SHA256)
		require.Nil(t, proof)
		require.ErrorContains(t, err, "invalid tx index")
	})

	t.Run("Test VerifyTxProof ok", func(t *testing.T) {
		signer, verifier := testsig.CreateSignerAndVerifier(t)
		block := createBlock(t, "test", signer)
		proof, err := NewTxRecordProof(block, 0, crypto.SHA256)
		require.NoError(t, err)

		tb := NewTrustBase(t, verifier)
		require.NoError(t, VerifyTxProof(proof, tb, crypto.SHA256))
	})

	t.Run("Test tx record proof is nil", func(t *testing.T) {
		_, verifier := testsig.CreateSignerAndVerifier(t)
		tb := NewTrustBase(t, verifier)
		require.EqualError(t, VerifyTxProof(nil, tb, crypto.SHA256), "transaction record proof is nil")
	})

	t.Run("Test tx record is nil", func(t *testing.T) {
		_, verifier := testsig.CreateSignerAndVerifier(t)
		tb := NewTrustBase(t, verifier)
		proof := &TxRecordProof{TxProof: &TxProof{}}
		require.EqualError(t, VerifyTxProof(proof, tb, crypto.SHA256), "transaction record is nil")
	})

	t.Run("Test tx has failed", func(t *testing.T) {
		_, verifier := testsig.CreateSignerAndVerifier(t)
		tb := NewTrustBase(t, verifier)
		txr := &TransactionRecord{ServerMetadata: &ServerMetadata{SuccessIndicator: TxStatusFailed}, TransactionOrder: &TransactionOrder{}}
		proof := &TxRecordProof{TxRecord: txr, TxProof: &TxProof{}}
		require.EqualError(t, VerifyTxProof(proof, tb, crypto.SHA256), "transaction failed")
	})

	t.Run("Test tx out of gas", func(t *testing.T) {
		_, verifier := testsig.CreateSignerAndVerifier(t)
		tb := NewTrustBase(t, verifier)
		txr := &TransactionRecord{ServerMetadata: &ServerMetadata{SuccessIndicator: TxErrOutOfGas}, TransactionOrder: &TransactionOrder{}}
		proof := &TxRecordProof{TxRecord: txr, TxProof: &TxProof{}}
		require.EqualError(t, VerifyTxProof(proof, tb, crypto.SHA256), "transaction failed")
	})

	t.Run("Test tx order is nil", func(t *testing.T) {
		_, verifier := testsig.CreateSignerAndVerifier(t)
		tb := NewTrustBase(t, verifier)
		txr := &TransactionRecord{ServerMetadata: &ServerMetadata{SuccessIndicator: TxStatusSuccessful}}
		proof := &TxRecordProof{TxRecord: txr, TxProof: &TxProof{}}
		require.EqualError(t, VerifyTxProof(proof, tb, crypto.SHA256), "transaction order is nil")
	})

	t.Run("Test VerifyTxProof error, invalid system id", func(t *testing.T) {
		signer, verifier := testsig.CreateSignerAndVerifier(t)
		block := createBlock(t, "test", signer)
		proof, err := NewTxRecordProof(block, 0, crypto.SHA256)
		require.NoError(t, err)

		tb := NewTrustBase(t, verifier)
		uc, err := proof.TxProof.getUCv1()
		require.NoError(t, err)
		uc.UnicityTreeCertificate.SystemIdentifier = SystemID(1)
		proof.TxProof.UnicityCertificate, err = uc.MarshalCBOR()
		require.NoError(t, err)
		require.EqualError(t, VerifyTxProof(proof, tb, crypto.SHA256),
			"invalid unicity certificate: unicity certificate validation failed: unicity tree certificate validation failed: invalid system identifier: expected 01000001, got 00000001")
	})

	t.Run("Test VerifyTxProof error, invalid block hash", func(t *testing.T) {
		signer, verifier := testsig.CreateSignerAndVerifier(t)
		block := createBlock(t, "test", signer)
		proof, err := NewTxRecordProof(block, 0, crypto.SHA256)
		require.NoError(t, err)

		tb := NewTrustBase(t, verifier)
		proof.TxProof.BlockHeaderHash = make([]byte, 32)
		require.EqualError(t, VerifyTxProof(proof, tb, crypto.SHA256), "proof block hash does not match to block hash in unicity certificate")
	})
}

func createBlock(t *testing.T, id string, signer abcrypto.Signer) *Block {
	sdrs := &PartitionDescriptionRecord{
		SystemIdentifier: systemID,
		T2Timeout:        2500 * time.Millisecond,
	}
	inputRecord := &InputRecord{
		Version:         1,
		PreviousHash:    []byte{0, 0, 1},
		Hash:            []byte{0, 0, 2},
		SummaryValue:    []byte{0, 0, 4},
		RoundNumber:     1,
		SumOfEarnedFees: 2,
	}
	txr1 := createTransactionRecord(createTransactionOrder(t), 1)
	txr2 := createTransactionRecord(createTransactionOrder(t), 1)
	uc, err := (&UnicityCertificate{Version: 1, InputRecord: inputRecord}).MarshalCBOR()
	require.NoError(t, err)
	block := &Block{
		Header: &Header{
			SystemID:          systemID,
			ProposerID:        "proposer123",
			PreviousBlockHash: []byte{1, 2, 3},
		},
		Transactions:       []*TransactionRecord{txr1, txr2},
		UnicityCertificate: uc,
	}
	// calculate block hash
	inputRecord, err = block.CalculateBlockHash(crypto.SHA256)
	require.NoError(t, err)
	block.UnicityCertificate, err = createUnicityCertificate(t, id, signer, inputRecord, sdrs).MarshalCBOR()
	require.NoError(t, err)
	return block
}
