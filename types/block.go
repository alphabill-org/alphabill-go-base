package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/tree/mt"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
	"github.com/alphabill-org/alphabill-go-base/util"
)

var (
	errBlockIsNil             = errors.New("block is nil")
	errBlockHeaderIsNil       = errors.New("block header is nil")
	errPrevBlockHashIsNil     = errors.New("previous block hash is nil")
	errBlockProposerIDMissing = errors.New("block proposer node identifier is missing")
	errTransactionsIsNil      = errors.New("transactions is nil")
	errPartitionIDIsNil       = errors.New("partition identifier is unassigned")
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
	err := Cbor.Unmarshal(b.UnicityCertificate, uc)
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

	if stateHash == nil {
		return nil, fmt.Errorf("invalid block: state hash is nil")
	}
	if prevStateHash == nil {
		return nil, fmt.Errorf("invalid block: previous state hash is nil")
	}
	// 0H - if there are no transactions and state does not change
	if len(txs) == 0 && bytes.Equal(prevStateHash, stateHash) {
		return make([]byte, algorithm.Size()), nil
	}
	// init transactions merkle root to 0H
	var merkleRoot = make([]byte, algorithm.Size())
	// calculate Merkle tree of transactions if any
	if len(txs) > 0 {
		// calculate merkle tree root hash from transactions
		tree := mt.New(algorithm, txs)
		merkleRoot = tree.GetRootHash()
	}
	// header hash || UC.IR.h′ || UC.IR.h || 0H - block Merkle tree root 0H
	headerHash := h.Hash(algorithm)
	hasher := algorithm.New()
	hasher.Write(headerHash)
	hasher.Write(prevStateHash)
	hasher.Write(stateHash)
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
	uc, err := b.getUCv1()
	if err != nil {
		return fmt.Errorf("unicity certificate error: %w", err)
	}
	if err := uc.IsValid(algorithm, b.Header.PartitionID, systemDescriptionHash); err != nil {
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
	return Cbor.MarshalTaggedValue(BlockTag, (*alias)(h))
}

func (h *Header) UnmarshalCBOR(data []byte) error {
	type alias Header
	if err := Cbor.Unmarshal(data, (*alias)(h)); err != nil {
		return err
	}
	return nil
}

func (h *Header) Hash(algorithm crypto.Hash) []byte {
	if h == nil {
		return nil
	}
	hasher := algorithm.New()
	hasher.Write(util.Uint32ToBytes(h.Version))
	hasher.Write(h.PartitionID.Bytes())
	h.ShardID.AddToHasher(hasher)
	hasher.Write(h.PreviousBlockHash)
	hasher.Write([]byte(h.ProposerID))
	return hasher.Sum(nil)
}

func (h *Header) IsValid() error {
	if h == nil {
		return errBlockHeaderIsNil
	}
	if h.Version == 0 {
		return ErrInvalidVersion(h)
	}
	if h.PartitionID == 0 {
		return errPartitionIDIsNil
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
