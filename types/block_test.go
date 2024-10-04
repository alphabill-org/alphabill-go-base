package types

import (
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testsig "github.com/alphabill-org/alphabill-go-base/testutils/sig"
)

func TestBlock_GetBlockFees(t *testing.T) {
	t.Run("Block is nil", func(t *testing.T) {
		var b *Block = nil
		require.EqualValues(t, 0, b.GetBlockFees(), "GetBlockFees()")
	})
	t.Run("UC is nil", func(t *testing.T) {
		b := &Block{}
		require.EqualValues(t, 0, b.GetBlockFees(), "GetBlockFees()")
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{UnicityCertificate: uc}
		require.EqualValues(t, 0, b.GetBlockFees(), "GetBlockFees()")
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{SumOfEarnedFees: 10}}).MarshalCBOR()
		require.NoError(t, err)
		fmt.Printf("uc: %X\n", uc)
		b := &Block{UnicityCertificate: uc}
		require.EqualValues(t, 10, b.GetBlockFees(), "GetBlockFees()")
	})
}

func TestBlock_GetProposerID(t *testing.T) {
	t.Run("Block is nil", func(t *testing.T) {
		var b *Block = nil
		require.Equal(t, "", b.GetProposerID())
	})
	t.Run("Header is nil", func(t *testing.T) {
		b := &Block{}
		require.Equal(t, "", b.GetProposerID())
	})
	t.Run("Proposer not set", func(t *testing.T) {
		b := &Block{Header: &Header{}}
		require.Equal(t, "", b.GetProposerID())
	})
	t.Run("Proposer equal", func(t *testing.T) {
		b := &Block{Header: &Header{ProposerID: "test"}}
		require.Equal(t, "test", b.GetProposerID())
	})
}

func TestBlock_GetRoundNumber(t *testing.T) {
	t.Run("block is nil", func(t *testing.T) {
		var b *Block = nil
		require.EqualValues(t, 0, b.GetRoundNumber())
	})
	t.Run("UC is nil", func(t *testing.T) {
		b := &Block{}
		require.EqualValues(t, 0, b.GetRoundNumber())
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{UnicityCertificate: uc}
		require.EqualValues(t, 0, b.GetRoundNumber())
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{RoundNumber: 10}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{UnicityCertificate: uc}
		require.EqualValues(t, 10, b.GetRoundNumber())
	})
}

func TestBlock_SystemID(t *testing.T) {
	t.Run("Block is nil", func(t *testing.T) {
		var b *Block = nil
		require.EqualValues(t, 0, b.SystemID())
	})
	t.Run("Header is nil", func(t *testing.T) {
		b := &Block{}
		require.EqualValues(t, 0, b.SystemID())
	})
	t.Run("SystemID not set", func(t *testing.T) {
		b := &Block{Header: &Header{}}
		require.EqualValues(t, 0, b.SystemID())
	})
	t.Run("SystemID equal", func(t *testing.T) {
		b := &Block{Header: &Header{
			SystemID: SystemID(5),
		}}
		require.Equal(t, SystemID(5), b.SystemID())
	})
}

func TestBlock_IsValid(t *testing.T) {
	t.Run("Block is nil", func(t *testing.T) {
		var b *Block = nil
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "block is nil")
	})
	t.Run("Header is nil", func(t *testing.T) {
		b := &Block{}
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "block error: block header is nil")
	})
	t.Run("Transactions is nil", func(t *testing.T) {
		b := &Block{
			Header: &Header{
				SystemID:          SystemID(1),
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
		}
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "transactions is nil")
	})
	t.Run("UC is nil", func(t *testing.T) {
		b := &Block{
			Header: &Header{
				SystemID:          SystemID(1),
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions: make([]*TransactionRecord, 0),
		}
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "unicity certificate is nil")
	})
	t.Run("input record is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				SystemID:          SystemID(1),
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "unicity certificate validation failed: input record error: input record is nil")
	})
	t.Run("valid block", func(t *testing.T) {
		signer, _ := testsig.CreateSignerAndVerifier(t)
		sdrs := &PartitionDescriptionRecord{
			SystemIdentifier: systemID,
			T2Timeout:        2500 * time.Millisecond,
		}
		inputRecord := &InputRecord{
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     1,
			SumOfEarnedFees: 2,
		}
		txr1 := createTransactionRecord(createTxOrder(t), 1)
		txr2 := createTransactionRecord(createTxOrder(t), 2)
		uc, err := (&UnicityCertificate{InputRecord: inputRecord}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				SystemID:          systemID,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       []*TransactionRecord{txr1, txr2},
			UnicityCertificate: uc,
		}
		// calculate block hash
		blockhash, err := b.Hash(crypto.SHA256)
		require.NoError(t, err)
		inputRecord.BlockHash = blockhash
		uc, err = createUnicityCertificate(t, "test", signer, inputRecord, sdrs).MarshalCBOR()
		require.NoError(t, err)
		b.UnicityCertificate = uc
		require.NoError(t, b.IsValid(crypto.SHA256, sdrs.Hash(crypto.SHA256)))
	})
	t.Run("invalid block hash", func(t *testing.T) {
		signer, _ := testsig.CreateSignerAndVerifier(t)
		sdrs := &PartitionDescriptionRecord{
			SystemIdentifier: systemID,
			T2Timeout:        2500 * time.Millisecond,
		}
		inputRecord := &InputRecord{
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			SummaryValue:    []byte{0, 0, 4},
			RoundNumber:     1,
			SumOfEarnedFees: 2,
		}
		txr1 := createTransactionRecord(createTxOrder(t), 1)
		txr2 := createTransactionRecord(createTxOrder(t), 2)
		uc, err := (&UnicityCertificate{InputRecord: inputRecord}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				SystemID:          systemID,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       []*TransactionRecord{txr1, txr2},
			UnicityCertificate: uc,
		}
		// calculate block hash
		blockhash, err := b.Hash(crypto.SHA256)
		require.NoError(t, err)
		inputRecord.BlockHash = blockhash
		uc, err = createUnicityCertificate(t, "test", signer, inputRecord, sdrs).MarshalCBOR()
		require.NoError(t, err)
		b.UnicityCertificate = uc
		// remove a tx from block and make sure that the validation fails
		b.Transactions = b.Transactions[1:]
		require.EqualError(t, b.IsValid(crypto.SHA256, sdrs.Hash(crypto.SHA256)), "block hash does not match to the block hash in the unicity certificate input record")
	})
}

func TestBlock_Hash(t *testing.T) {
	t.Run("missing header", func(t *testing.T) {
		b := &Block{}
		hash, err := b.Hash(crypto.SHA256)
		require.Nil(t, hash)
		require.EqualError(t, err, "invalid block: block header is nil")
	})
	t.Run("state hash is missing", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				SystemID:          SystemID(1),
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		hash, err := b.Hash(crypto.SHA256)
		require.Nil(t, hash)
		require.EqualError(t, err, "invalid block: state hash is nil")
	})
	t.Run("previous state hash is missing", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{
			Hash: []byte{1, 1, 1},
		}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				SystemID:          SystemID(1),
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		hash, err := b.Hash(crypto.SHA256)
		require.Nil(t, hash)
		require.EqualError(t, err, "invalid block: previous state hash is nil")
	})
	t.Run("previous state hash is missing", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{
			Hash:         []byte{1, 1, 1},
			PreviousHash: []byte{1, 1, 1},
		}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				SystemID:          SystemID(1),
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		hash, err := b.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, hash, make([]byte, 32))
	})

	t.Run("hash - ok", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{
			Hash:         []byte{1, 1, 1},
			PreviousHash: []byte{2, 2, 2},
		}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				SystemID:          SystemID(1),
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		hash, err := b.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.NotNil(t, hash)
	})
}

func TestBlock_Size(t *testing.T) {
	// size of an empty block must be zero
	b := Block{}
	size, err := b.Size()
	require.NoError(t, err)
	require.EqualValues(t, 0, size)

	txr := createTransactionRecord(createTxOrder(t), 1)
	buf, err := txr.Bytes()
	require.NoError(t, err)
	txSize := len(buf)

	// add an txr to the block - size must be != 0 now
	b.Transactions = append(b.Transactions, txr)
	size, err = b.Size()
	require.NoError(t, err)
	require.EqualValues(t, txSize, size)
	// adding the same txr once more (not valid but not important
	// in this context) should double the size
	b.Transactions = append(b.Transactions, txr)
	size, err = b.Size()
	require.NoError(t, err)
	require.EqualValues(t, 2*txSize, size)
	// second consecutive call must return the same value
	size, err = b.Size()
	require.NoError(t, err)
	require.EqualValues(t, 2*txSize, size)
}

func TestHeader_IsValid(t *testing.T) {
	t.Run("header is nil", func(t *testing.T) {
		var h *Header = nil
		require.EqualError(t, h.IsValid(), "block header is nil")
	})
	t.Run("system identifier is nil", func(t *testing.T) {
		h := &Header{}
		require.EqualError(t, h.IsValid(), "system identifier is unassigned")
	})
	t.Run("previous block hash is nil", func(t *testing.T) {
		h := &Header{
			SystemID: SystemID(2),
		}
		require.EqualError(t, h.IsValid(), "previous block hash is nil")
	})
	t.Run("proposer is missing", func(t *testing.T) {
		h := &Header{
			SystemID:          SystemID(2),
			PreviousBlockHash: []byte{1, 2, 3},
		}
		require.EqualError(t, h.IsValid(), "block proposer node identifier is missing")
	})
	t.Run("valid", func(t *testing.T) {
		h := &Header{
			SystemID:          SystemID(2),
			PreviousBlockHash: []byte{1, 2, 3},
			ProposerID:        "test",
		}
		require.NoError(t, h.IsValid())
	})
}

func TestHeader_Hash(t *testing.T) {
	hdr := Header{
		SystemID:          SystemID(2),
		ShardID:           ShardID{bits: []byte{0b1110_0000}, length: 3},
		ProposerID:        "test",
		PreviousBlockHash: []byte{2, 2, 2},
	}
	headerHash := hdr.Hash(crypto.SHA256)

	// each call must return the same value
	require.EqualValues(t, headerHash, hdr.Hash(crypto.SHA256))
	// different hash algorithm should return different value
	require.NotEqualValues(t, headerHash, hdr.Hash(crypto.SHA512))

	// make a copy of the struct - must get the same value as original
	hdr2 := hdr // note that "hdr" is not a pointer!
	require.EqualValues(t, headerHash, hdr2.Hash(crypto.SHA256))

	// change field value in the copy - hash must change
	hdr2.ProposerID = "foo"
	require.NotEqualValues(t, headerHash, hdr2.Hash(crypto.SHA256))

	hdr2.ProposerID = hdr.ProposerID // restore original value
	hdr2.ShardID, _ = hdr.ShardID.Split()
	require.NotEqualValues(t, headerHash, hdr2.Hash(crypto.SHA256))
}

func TestBlock_InputRecord(t *testing.T) {
	t.Run("err: block is nil", func(t *testing.T) {
		var b *Block = nil
		got, err := b.InputRecord()
		require.ErrorIs(t, err, errBlockIsNil)
		require.Nil(t, got)
	})
	t.Run("err: UC is nil", func(t *testing.T) {
		b := &Block{}
		got, err := b.InputRecord()
		require.ErrorIs(t, err, ErrUCIsNil)
		require.Nil(t, got)
	})
	t.Run("err: IR is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			UnicityCertificate: uc,
		}
		got, err := b.InputRecord()
		require.ErrorIs(t, err, ErrInputRecordIsNil)
		require.Nil(t, got)
	})
	t.Run("ok", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			UnicityCertificate: uc,
		}
		got, err := b.InputRecord()
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}
