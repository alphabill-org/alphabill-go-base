package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/tree/mt"
)

var (
	errBlockIsNil             = errors.New("block is nil")
	errBlockHeaderIsNil       = errors.New("block header is nil")
	errPrevBlockHashIsNil     = errors.New("previous block hash is nil")
	errBlockProposerIDMissing = errors.New("block proposer node identifier is missing")
	errTransactionsIsNil      = errors.New("transactions is nil")
	errSystemIDIsNil          = errors.New("system identifier is unassigned")
)

type (
	Block struct {
		_                  struct{} `cbor:",toarray"`
		Header             *Header
		Transactions       []*TransactionRecord
		UnicityCertificate TaggedCBOR
	}

	Header struct {
		_                 struct{} `cbor:",toarray"`
		SystemID          SystemID
		ShardID           ShardID
		ProposerID        string
		PreviousBlockHash []byte
	}
)

func (b *Block) getUCv1() *UnicityCertificate {
	uc := &UnicityCertificate{}
	err := Cbor.Unmarshal(b.UnicityCertificate, uc)
	if err != nil {
		return nil // or panic?
	}
	return uc
}

// Hash returns the hash of the block. Hash of a block is computed as hash of block header fields and tree hash
// of transactions.
func (b *Block) Hash(algorithm crypto.Hash) ([]byte, error) {
	if err := b.Header.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid block: %w", err)
	}
	uc := b.getUCv1()
	if uc.GetStateHash() == nil {
		return nil, fmt.Errorf("invalid block: state hash is nil")
	}
	if uc.GetPreviousStateHash() == nil {
		return nil, fmt.Errorf("invalid block: previous state hash is nil")
	}
	// 0H - if there are no transactions and state does not change
	if len(b.Transactions) == 0 && bytes.Equal(uc.InputRecord.PreviousHash, uc.InputRecord.Hash) {
		return make([]byte, algorithm.Size()), nil
	}
	// init transactions merkle root to 0H
	var merkleRoot = make([]byte, algorithm.Size())
	// calculate Merkle tree of transactions if any
	if len(b.Transactions) > 0 {
		// calculate merkle tree root hash from transactions
		tree := mt.New(algorithm, b.Transactions)
		merkleRoot = tree.GetRootHash()
	}
	// header hash || UC.IR.h′ || UC.IR.h || 0H - block Merkle tree root 0H
	headerHash := b.HeaderHash(algorithm)
	hasher := algorithm.New()
	hasher.Write(headerHash)
	hasher.Write(uc.InputRecord.PreviousHash)
	hasher.Write(uc.InputRecord.Hash)
	hasher.Write(merkleRoot)
	return hasher.Sum(nil), nil
}

func (b *Block) HeaderHash(algorithm crypto.Hash) []byte {
	return b.Header.Hash(algorithm)
}

/*
Size returns Block Size value used in Certification Request.
*/
func (b *Block) Size() (bs uint64, _ error) {
	for x, v := range b.Transactions {
		buf, err := v.Bytes()
		if err != nil {
			return 0, fmt.Errorf("failed to get binary size of the transaction %d in the block: %w", x, err)
		}
		bs += uint64(len(buf))
	}
	return bs, nil
}

func (b *Block) GetRoundNumber() uint64 {
	if b != nil {
		return b.getUCv1().GetRoundNumber()
	}
	return 0
}

func (b *Block) GetBlockFees() uint64 {
	if b != nil {
		return b.getUCv1().GetFeeSum()
	}
	return 0
}

func (b *Block) InputRecord() (*InputRecord, error) {
	if b == nil {
		return nil, errBlockIsNil
	}
	uc := b.getUCv1()
	if uc == nil {
		return nil, ErrUCIsNil
	}
	if uc.InputRecord == nil {
		return nil, ErrInputRecordIsNil
	}
	return uc.InputRecord, nil
}

func (b *Block) IsValid(algorithm crypto.Hash, systemDescriptionHash []byte) error {
	if b == nil {
		return errBlockIsNil
	}
	if err := b.Header.IsValid(); err != nil {
		return fmt.Errorf("block error: %w", err)
	}
	if b.Transactions == nil {
		return errTransactionsIsNil
	}
	uc := b.getUCv1()
	if uc == nil {
		return fmt.Errorf("unicity certificate is nil")
	}
	if err := uc.IsValid(algorithm, b.Header.SystemID, systemDescriptionHash); err != nil {
		return fmt.Errorf("unicity certificate validation failed: %w", err)
	}
	// match block hash to input record
	hash, err := b.Hash(algorithm)
	if err != nil {
		return fmt.Errorf("block hash calculation failed: %w", err)
	}
	if !bytes.Equal(hash, uc.InputRecord.BlockHash) {
		return fmt.Errorf("block hash does not match to the block hash in the unicity certificate input record")
	}
	return nil
}

func (b *Block) GetProposerID() string {
	if b == nil || b.Header == nil {
		return ""
	}
	return b.Header.ProposerID
}

func (b *Block) SystemID() SystemID {
	if b == nil || b.Header == nil {
		return 0
	}
	return b.Header.SystemID
}

func (h *Header) Hash(algorithm crypto.Hash) []byte {
	if h == nil {
		return nil
	}
	hasher := algorithm.New()
	hasher.Write(h.SystemID.Bytes())
	h.ShardID.AddToHasher(hasher)
	hasher.Write(h.PreviousBlockHash)
	hasher.Write([]byte(h.ProposerID))
	return hasher.Sum(nil)
}

func (h *Header) IsValid() error {
	if h == nil {
		return errBlockHeaderIsNil
	}
	if h.SystemID == 0 {
		return errSystemIDIsNil
	}
	// skip shard identifier for now, it is not used
	if h.PreviousBlockHash == nil {
		return errPrevBlockHashIsNil
	}
	if len(h.ProposerID) == 0 {
		return errBlockProposerIDMissing
	}
	return nil
}
