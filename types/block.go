package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/tree/mt"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var (
	errBlockIsNil             = errors.New("block is nil")
	errBlockHeaderIsNil       = errors.New("block header is nil")
	errBlockProposerIDMissing = errors.New("block proposer node identifier is missing")
	errTransactionsIsNil      = errors.New("transactions is nil")
	errPartitionIDIsNil       = errors.New("partition identifier is unassigned")
)

type (
	Block struct {
		_                  struct{} `cbor:",toarray"`
		Header             *Header
		Transactions       []*TransactionRecord
		UnicityCertificate cbor.TaggedCBOR
	}

	Header struct {
		_                 struct{} `cbor:",toarray"`
		Version           ABVersion
		PartitionID       PartitionID
		ShardID           ShardID
		ProposerID        string
		PreviousBlockHash hex.Bytes
	}
)

func (b *Block) getUCv1() (*UnicityCertificate, error) {
	if b == nil {
		return nil, errBlockIsNil
	}
	if b.UnicityCertificate == nil {
		return nil, ErrUnicityCertificateIsNil
	}
	uc := &UnicityCertificate{}
	err := cbor.Unmarshal(b.UnicityCertificate, uc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal unicity certificate: %w", err)
	}
	return uc, nil
}

// CalculateBlockHash calculates the block hash, updates UC and returns the updated input record with the block hash.
func (b *Block) CalculateBlockHash(algorithm crypto.Hash) (*InputRecord, error) {
	uc, err := b.getUCv1()
	if err != nil {
		return nil, fmt.Errorf("failed to get unicity certificate: %w", err)
	}
	ir := uc.InputRecord
	if ir == nil {
		return nil, ErrInputRecordIsNil
	}
	// calculate block hash
	hash, err := BlockHash(algorithm, b.Header, b.Transactions, ir.Hash, ir.PreviousHash)
	if err != nil {
		return nil, fmt.Errorf("block hash calculation failed: %w", err)
	}
	ir.BlockHash = hash
	b.UnicityCertificate, err = uc.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal unicity certificate: %w", err)
	}
	return ir, nil
}

// BlockHash returns the hash of the block. Hash of a block is computed as hash of block header fields and tree hash
// of transactions.
func BlockHash(algorithm crypto.Hash, h *Header, txs []*TransactionRecord, stateHash []byte, prevStateHash []byte) ([]byte, error) {
	if err := h.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid block: %w", err)
	}

	// ⊥ - if there are no transactions and state does not change
	if len(txs) == 0 && bytes.Equal(prevStateHash, stateHash) {
		return nil, nil
	}
	// init transactions merkle root to ⊥
	var merkleRoot []byte
	// calculate Merkle tree of transactions if any
	if len(txs) > 0 {
		// calculate merkle tree root hash from transactions
		tree, err := mt.New(algorithm, txs)
		if err != nil {
			return nil, fmt.Errorf("failed to create Merkle tree: %w", err)
		}
		merkleRoot = tree.GetRootHash()
	}
	// header hash || UC.IR.h′ || UC.IR.h || tree hash of transactions
	hasher := abhash.New(algorithm.New())
	headerHash, err := h.Hash(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to hash block header: %w", err)
	}
	hasher.Write(headerHash)
	hasher.Write(prevStateHash)
	hasher.Write(stateHash)
	hasher.Write(merkleRoot)
	return hasher.Sum()
}

func (b *Block) HeaderHash(algorithm crypto.Hash) ([]byte, error) {
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

func (b *Block) GetRoundNumber() (uint64, error) {
	uc, err := b.getUCv1()
	if err != nil {
		return 0, fmt.Errorf("block round number: %w", err)
	}
	return uc.GetRoundNumber(), nil
}

func (b *Block) GetBlockFees() (uint64, error) {
	uc, err := b.getUCv1()
	if err != nil {
		return 0, fmt.Errorf("block fees: %w", err)
	}
	return uc.GetFeeSum(), nil
}

func (b *Block) InputRecord() (*InputRecord, error) {
	if b == nil {
		return nil, errBlockIsNil
	}
	uc, err := b.getUCv1()
	if err != nil {
		return nil, fmt.Errorf("block input record: %w", err)
	}
	if uc.InputRecord == nil {
		return nil, ErrInputRecordIsNil
	}
	return uc.InputRecord, nil
}

func (b *Block) IsValid(algorithm crypto.Hash, shardConfHash []byte) error {
	if b == nil {
		return errBlockIsNil
	}
	if err := b.Header.IsValid(); err != nil {
		return fmt.Errorf("block error: %w", err)
	}
	if b.Transactions == nil {
		return errTransactionsIsNil
	}
	uc, err := b.getUCv1()
	if err != nil {
		return fmt.Errorf("unicity certificate error: %w", err)
	}
	if err := uc.IsValid(b.Header.PartitionID, shardConfHash); err != nil {
		return fmt.Errorf("unicity certificate validation failed: %w", err)
	}
	// match block hash to input record
	hash, err := BlockHash(algorithm, b.Header, b.Transactions, uc.GetStateHash(), uc.GetPreviousStateHash())
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

func (b *Block) PartitionID() PartitionID {
	if b == nil || b.Header == nil {
		return 0
	}
	return b.Header.PartitionID
}

func (h *Header) GetVersion() ABVersion {
	if h != nil && h.Version > 0 {
		return h.Version
	}
	return 1
}

func (h *Header) MarshalCBOR() ([]byte, error) {
	type alias Header
	if h.Version == 0 {
		h.Version = h.GetVersion()
	}
	return cbor.MarshalTaggedValue(BlockTag, (*alias)(h))
}

func (h *Header) UnmarshalCBOR(data []byte) error {
	type alias Header
	if err := cbor.UnmarshalTaggedValue(BlockTag, data, (*alias)(h)); err != nil {
		return fmt.Errorf("failed to unmarshal block header: %w", err)
	}
	return EnsureVersion(h, h.Version, 1)
}

func (h *Header) Hash(algorithm crypto.Hash) ([]byte, error) {
	if h == nil {
		return nil, errBlockHeaderIsNil
	}
	hasher := abhash.New(algorithm.New())
	hasher.Write(h)
	return hasher.Sum()
}

func (h *Header) IsValid() error {
	if h == nil {
		return errBlockHeaderIsNil
	}
	if h.Version != 1 {
		return ErrInvalidVersion(h)
	}
	if h.PartitionID == 0 {
		return errPartitionIDIsNil
	}
	// skip shard identifier for now, it is not used
	if len(h.ProposerID) == 0 {
		return errBlockProposerIDMissing
	}
	return nil
}
