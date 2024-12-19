package types

import (
	"crypto"
	"testing"
	"time"

	testsig "github.com/alphabill-org/alphabill-go-base/testutils/sig"
	"github.com/alphabill-org/alphabill-go-base/tree/mt"
	"github.com/stretchr/testify/require"
)

func TestBlock_GetBlockFees(t *testing.T) {
	t.Run("Block is nil", func(t *testing.T) {
		var b *Block = nil
		_, err := b.GetBlockFees()
		require.EqualError(t, err, "block fees: block is nil")
	})
	t.Run("UC is nil", func(t *testing.T) {
		b := &Block{}
		_, err := b.GetBlockFees()
		require.EqualError(t, err, "block fees: unicity certificate is nil")
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{UnicityCertificate: uc}
		fees, err := b.GetBlockFees()
		require.NoError(t, err)
		require.EqualValues(t, 0, fees, "GetBlockFees()")
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{SumOfEarnedFees: 10}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{UnicityCertificate: uc}
		fees, err := b.GetBlockFees()
		require.NoError(t, err)
		require.EqualValues(t, 10, fees, "GetBlockFees()")
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
		b := &Block{Header: &Header{Version: 1}}
		require.Equal(t, "", b.GetProposerID())
	})
	t.Run("Proposer equal", func(t *testing.T) {
		b := &Block{Header: &Header{Version: 1, ProposerID: "test"}}
		require.Equal(t, "test", b.GetProposerID())
	})
}

func TestBlock_GetRoundNumber(t *testing.T) {
	t.Run("block is nil", func(t *testing.T) {
		var b *Block = nil
		_, err := b.GetRoundNumber()
		require.ErrorIs(t, err, errBlockIsNil)
	})
	t.Run("UC is nil", func(t *testing.T) {
		b := &Block{}
		_, err := b.GetRoundNumber()
		require.ErrorIs(t, err, ErrUnicityCertificateIsNil)
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{UnicityCertificate: uc}
		rn, err := b.GetRoundNumber()
		require.NoError(t, err)
		require.EqualValues(t, 0, rn)
	})
	t.Run("InputRecord is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{RoundNumber: 10}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{UnicityCertificate: uc}
		rn, err := b.GetRoundNumber()
		require.NoError(t, err)
		require.EqualValues(t, 10, rn)
	})
}

func TestBlock_PartitionID(t *testing.T) {
	t.Run("Block is nil", func(t *testing.T) {
		var b *Block = nil
		require.EqualValues(t, 0, b.PartitionID())
	})
	t.Run("Header is nil", func(t *testing.T) {
		b := &Block{}
		require.EqualValues(t, 0, b.PartitionID())
	})
	t.Run("PartitionID not set", func(t *testing.T) {
		b := &Block{Header: &Header{Version: 1}}
		require.EqualValues(t, 0, b.PartitionID())
	})
	t.Run("PartitionID equal", func(t *testing.T) {
		b := &Block{Header: &Header{
			Version:     1,
			PartitionID: 5,
		}}
		require.Equal(t, PartitionID(5), b.PartitionID())
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
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
		}
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "transactions is nil")
	})
	t.Run("UC is nil", func(t *testing.T) {
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions: make([]*TransactionRecord, 0),
		}
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "unicity certificate error: unicity certificate is nil")
	})
	t.Run("input record is nil", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		require.EqualError(t, b.IsValid(crypto.SHA256, nil), "unicity certificate validation failed: invalid input record: input record is nil")
	})
	t.Run("valid block", func(t *testing.T) {
		signer, _ := testsig.CreateSignerAndVerifier(t)
		sdrs := &PartitionDescriptionRecord{
			Version:     1,
			PartitionID: partitionID,
			T2Timeout:   2500 * time.Millisecond,
		}
		inputRecord := &InputRecord{
			Version:         1,
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			SummaryValue:    []byte{0, 0, 4},
			Timestamp:       NewTimestamp(),
			RoundNumber:     1,
			SumOfEarnedFees: 2,
		}
		txr1 := createTransactionRecord(t, createTransactionOrder(t), 1)
		txr2 := createTransactionRecord(t, createTransactionOrder(t), 2)
		uc, err := (&UnicityCertificate{Version: 1, InputRecord: inputRecord}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       partitionID,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       []*TransactionRecord{txr1, txr2},
			UnicityCertificate: uc,
		}
		// calculate block hash
		inputRecord, err = b.CalculateBlockHash(crypto.SHA256)
		require.NoError(t, err)
		uc, err = createUnicityCertificate(t, "test", signer, inputRecord, make([]byte, 32), sdrs).MarshalCBOR()
		require.NoError(t, err)
		b.UnicityCertificate = uc
		h, err := sdrs.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.NoError(t, b.IsValid(crypto.SHA256, h))
	})
	t.Run("invalid block hash", func(t *testing.T) {
		signer, _ := testsig.CreateSignerAndVerifier(t)
		sdrs := &PartitionDescriptionRecord{
			Version:     1,
			PartitionID: partitionID,
			T2Timeout:   2500 * time.Millisecond,
		}
		inputRecord := &InputRecord{
			Version:         1,
			PreviousHash:    []byte{0, 0, 1},
			Hash:            []byte{0, 0, 2},
			SummaryValue:    []byte{0, 0, 4},
			Timestamp:       NewTimestamp(),
			RoundNumber:     1,
			SumOfEarnedFees: 2,
		}
		txr1 := createTransactionRecord(t, createTransactionOrder(t), 1)
		txr2 := createTransactionRecord(t, createTransactionOrder(t), 2)
		uc, err := (&UnicityCertificate{InputRecord: inputRecord}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       partitionID,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       []*TransactionRecord{txr1, txr2},
			UnicityCertificate: uc,
		}
		// calculate block hash
		inputRecord, err = b.CalculateBlockHash(crypto.SHA256)
		require.NoError(t, err)
		uc, err = createUnicityCertificate(t, "test", signer, inputRecord, make([]byte, 32), sdrs).MarshalCBOR()
		require.NoError(t, err)
		b.UnicityCertificate = uc
		// remove a tx from block and make sure that the validation fails
		b.Transactions = b.Transactions[1:]
		h, err := sdrs.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.EqualError(t, b.IsValid(crypto.SHA256, h), "block hash does not match to the block hash in the unicity certificate input record")
	})
}

func TestBlock_Hash(t *testing.T) {
	t.Run("missing header", func(t *testing.T) {
		b := &Block{}
		hash, err := BlockHash(crypto.SHA256, b.Header, b.Transactions, nil, nil)
		require.Nil(t, hash)
		require.EqualError(t, err, "invalid block: block header is nil")
	})
	t.Run("state hash is missing", func(t *testing.T) {
		uc := &UnicityCertificate{}
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions: make([]*TransactionRecord, 0),
		}
		hash, err := BlockHash(crypto.SHA256, b.Header, b.Transactions, uc.GetStateHash(), uc.GetPreviousStateHash())
		require.Nil(t, hash)
		require.EqualError(t, err, "invalid block: state hash is nil")
	})
	t.Run("previous state hash is missing", func(t *testing.T) {
		uc := &UnicityCertificate{InputRecord: &InputRecord{
			Hash: []byte{1, 1, 1},
		}}
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions: make([]*TransactionRecord, 0),
		}
		hash, err := BlockHash(crypto.SHA256, b.Header, b.Transactions, uc.GetStateHash(), uc.GetPreviousStateHash())
		require.Nil(t, hash)
		require.EqualError(t, err, "invalid block: previous state hash is nil")
	})
	t.Run("hash - ok, empty block", func(t *testing.T) {
		uc := &UnicityCertificate{InputRecord: &InputRecord{
			Hash:         []byte{1, 1, 1},
			PreviousHash: []byte{1, 1, 1},
		}}
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions: make([]*TransactionRecord, 0),
		}
		hash, err := BlockHash(crypto.SHA256, b.Header, b.Transactions, uc.GetStateHash(), uc.GetPreviousStateHash())
		require.NoError(t, err)
		require.Nil(t, hash)
	})

	t.Run("hash - ok", func(t *testing.T) {
		uc := &UnicityCertificate{InputRecord: &InputRecord{
			Hash:         []byte{1, 1, 1},
			PreviousHash: []byte{2, 2, 2},
		}}
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions: make([]*TransactionRecord, 0),
		}
		hash, err := BlockHash(crypto.SHA256, b.Header, b.Transactions, uc.GetStateHash(), uc.GetPreviousStateHash())
		require.NoError(t, err)
		require.NotNil(t, hash)
		require.NotEqual(t, hash, make([]byte, 32))
	})
}

func TestBlock_CalculateBlockHash(t *testing.T) {
	t.Run("missing ir", func(t *testing.T) {
		uc, err := (&UnicityCertificate{}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			UnicityCertificate: uc,
		}
		hash, err := b.CalculateBlockHash(crypto.SHA256)
		require.Nil(t, hash)
		require.EqualError(t, err, "input record is nil")
	})
	t.Run("state hash is missing", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		hash, err := b.CalculateBlockHash(crypto.SHA256)
		require.Nil(t, hash)
		require.EqualError(t, err, "block hash calculation failed: invalid block: state hash is nil")
	})
	t.Run("previous state hash is missing", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{
			Hash: []byte{1, 1, 1},
		}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		hash, err := b.CalculateBlockHash(crypto.SHA256)
		require.Nil(t, hash)
		require.EqualError(t, err, "block hash calculation failed: invalid block: previous state hash is nil")
	})
	t.Run("hash - ok, empty block", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{
			Hash:         []byte{1, 1, 1},
			PreviousHash: []byte{1, 1, 1},
		}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		ir, err := b.CalculateBlockHash(crypto.SHA256)
		require.NoError(t, err)
		require.Nil(t, ir.BlockHash)
	})

	t.Run("hash - ok", func(t *testing.T) {
		uc, err := (&UnicityCertificate{InputRecord: &InputRecord{
			Hash:         []byte{1, 1, 1},
			PreviousHash: []byte{2, 2, 2},
		}}).MarshalCBOR()
		require.NoError(t, err)
		b := &Block{
			Header: &Header{
				Version:           1,
				PartitionID:       1,
				ProposerID:        "test",
				PreviousBlockHash: []byte{1, 2, 3},
			},
			Transactions:       make([]*TransactionRecord, 0),
			UnicityCertificate: uc,
		}
		ir, err := b.CalculateBlockHash(crypto.SHA256)
		require.NoError(t, err)
		require.NotNil(t, ir.BlockHash)
		require.NotEqual(t, ir.BlockHash, make([]byte, 32))
	})
}

func TestBlock_Size(t *testing.T) {
	// size of an empty block must be zero
	b := Block{}
	size, err := b.Size()
	require.NoError(t, err)
	require.EqualValues(t, 0, size)

	txr := createTransactionRecord(t, createTransactionOrder(t), 1)
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
	t.Run("partition identifier is nil", func(t *testing.T) {
		h := &Header{Version: 1}
		require.EqualError(t, h.IsValid(), "partition identifier is unassigned")
	})
	t.Run("previous block hash is nil", func(t *testing.T) {
		h := &Header{
			Version:     1,
			PartitionID: 2,
		}
		require.EqualError(t, h.IsValid(), "previous block hash is nil")
	})
	t.Run("proposer is missing", func(t *testing.T) {
		h := &Header{
			Version:           1,
			PartitionID:       2,
			PreviousBlockHash: []byte{1, 2, 3},
		}
		require.EqualError(t, h.IsValid(), "block proposer node identifier is missing")
	})
	t.Run("valid", func(t *testing.T) {
		h := &Header{
			Version:           1,
			PartitionID:       2,
			PreviousBlockHash: []byte{1, 2, 3},
			ProposerID:        "test",
		}
		require.NoError(t, h.IsValid())
	})
}

func TestHeader_Hash(t *testing.T) {
	hdr := Header{
		Version:           1,
		PartitionID:       2,
		ShardID:           ShardID{bits: []byte{0b1110_0000}, length: 3},
		ProposerID:        "test",
		PreviousBlockHash: []byte{2, 2, 2},
	}
	headerHash, err := hdr.Hash(crypto.SHA256)
	require.NoError(t, err)

	// each call must return the same value
	require.EqualValues(t, headerHash, doHash(t, &hdr))
	// different hash algorithm should return different value
	h2, err := hdr.Hash(crypto.SHA512)
	require.NoError(t, err)
	require.NotEqualValues(t, headerHash, h2)

	// make a copy of the struct - must get the same value as original
	hdr2 := hdr // note that "hdr" is not a pointer!
	require.EqualValues(t, headerHash, doHash(t, &hdr2))

	// change field value in the copy - hash must change
	hdr2.ProposerID = "foo"
	require.NotEqualValues(t, headerHash, doHash(t, &hdr2))

	hdr2.ProposerID = hdr.ProposerID // restore original value
	hdr2.ShardID, _ = hdr.ShardID.Split()
	require.NotEqualValues(t, headerHash, doHash(t, &hdr2))
}

func doHash(t *testing.T, data mt.Data) []byte {
	t.Helper()
	h, err := data.Hash(crypto.SHA256)
	require.NoError(t, err)
	return h
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
		require.ErrorIs(t, err, ErrUnicityCertificateIsNil)
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

func TestBlock_CBOR(t *testing.T) {
	t.Run("empty block", func(t *testing.T) {
		b := Block{}
		blockBytes, err := Cbor.Marshal(b)
		require.NoError(t, err)
		require.NotNil(t, blockBytes)
		b2 := Block{}
		err = Cbor.Unmarshal(blockBytes, &b2)
		require.NoError(t, err)
		require.EqualValues(t, b, b2)
	})
	h := Header{
		Version:           1,
		PartitionID:       2,
		ShardID:           ShardID{},
		ProposerID:        "test",
		PreviousBlockHash: []byte{2, 2, 2},
	}
	t.Run("block with header", func(t *testing.T) {
		b := Block{Header: &h}
		blockBytes, err := Cbor.Marshal(b)
		require.NoError(t, err)
		require.NotNil(t, blockBytes)
		b2 := Block{}
		err = Cbor.Unmarshal(blockBytes, &b2)
		require.NoError(t, err)
		require.EqualValues(t, b, b2)
	})
	t.Run("block with transactions", func(t *testing.T) {
		txr := createTransactionRecord(t, createTransactionOrder(t), 1)
		b := Block{
			Header:       &h,
			Transactions: []*TransactionRecord{txr},
		}
		blockBytes, err := Cbor.Marshal(b)
		require.NoError(t, err)
		require.NotNil(t, blockBytes)
		b2 := Block{}
		err = Cbor.Unmarshal(blockBytes, &b2)
		require.NoError(t, err)
		require.EqualValues(t, b, b2)
	})
	t.Run("block with unicity certificate", func(t *testing.T) {
		uc := &UnicityCertificate{
			InputRecord: &InputRecord{
				Version:      1, // if version is not set here, the test fails (despite the fact it's a pointer)
				Hash:         []byte{1, 1, 1},
				PreviousHash: []byte{1, 1, 1},
			}}
		ucBytes, err := (uc).MarshalCBOR()
		require.NoError(t, err)
		b := Block{
			Header:             &h,
			UnicityCertificate: ucBytes,
		}
		blockBytes, err := Cbor.Marshal(b)
		require.NoError(t, err)
		require.NotNil(t, blockBytes)
		b2 := Block{}
		err = Cbor.Unmarshal(blockBytes, &b2)
		require.NoError(t, err)
		require.EqualValues(t, b, b2)

		uc2 := &UnicityCertificate{}
		err = Cbor.Unmarshal(b2.UnicityCertificate, uc2)
		require.NoError(t, err)
		require.EqualValues(t, uc, uc2)
	})
	t.Run("invalid version", func(t *testing.T) {
		h.Version = 2
		b := Block{Header: &h}
		blockBytes, err := Cbor.Marshal(b)
		require.NoError(t, err)
		require.NotNil(t, blockBytes)
		b2 := Block{}
		err = Cbor.Unmarshal(blockBytes, &b2)
		require.ErrorContains(t, err, "invalid version (type *types.Header), expected 1, got 2")
	})
}
