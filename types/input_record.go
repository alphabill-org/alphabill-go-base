package types

import (
	"bytes"
	"errors"
	"fmt"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var (
	ErrInputRecordIsNil      = errors.New("input record is nil")
	ErrHashIsNil             = errors.New("hash is nil")
	ErrBlockHashIsNil        = errors.New("block hash is nil")
	ErrPreviousHashIsNil     = errors.New("previous hash is nil")
	ErrSummaryValueIsNil     = errors.New("summary value is nil")
	ErrInvalidPartitionRound = errors.New("partition round is 0")
)

// Shard input record (IR) of a shard of a partition.
type InputRecord struct {
	_               struct{}  `cbor:",toarray"`
	Version         ABVersion `json:"version"`
	PreviousHash    hex.Bytes `json:"previousHash"`    // previously certified state hash
	Hash            hex.Bytes `json:"hash"`            // state hash to be certified
	BlockHash       hex.Bytes `json:"blockHash"`       // hash of the block
	SummaryValue    hex.Bytes `json:"summaryValue"`    // summary value to certified
	Timestamp       uint64    `json:"timestamp"`       // reference time for transaction validation
	RoundNumber     uint64    `json:"roundNumber"`     // shard's round number
	Epoch           uint64    `json:"epoch"`           // shard’s epoch number
	SumOfEarnedFees uint64    `json:"sumOfEarnedFees"` // sum of the actual fees over all transaction records in the block
}

func isZeroHash(hash []byte) bool {
	for _, b := range hash {
		if b != 0 {
			return false
		}
	}
	return true
}

func EqualIR(a, b *InputRecord) bool {
	return bytes.Equal(a.Bytes(), b.Bytes())
}

func AssertEqualIR(a, b *InputRecord) error {
	if a.Epoch != b.Epoch {
		return fmt.Errorf("epoch is different: %v vs %v", a.Epoch, b.Epoch)
	}
	if a.RoundNumber != b.RoundNumber {
		return fmt.Errorf("round number is different: %v vs %v", a.RoundNumber, b.RoundNumber)
	}
	if a.SumOfEarnedFees != b.SumOfEarnedFees {
		return fmt.Errorf("sum of fees is different: %v vs %v", a.SumOfEarnedFees, b.SumOfEarnedFees)
	}
	if a.Timestamp != b.Timestamp {
		return fmt.Errorf("timestamp is different: %d vs %d", a.Timestamp, b.Timestamp)
	}
	if !bytes.Equal(a.SummaryValue, b.SummaryValue) {
		return fmt.Errorf("summary value is different: %v vs %v", a.SummaryValue, b.SummaryValue)
	}
	if !bytes.Equal(a.PreviousHash, b.PreviousHash) {
		return fmt.Errorf("previous state hash is different: %X vs %X", a.PreviousHash, b.PreviousHash)
	}
	if !bytes.Equal(a.Hash, b.Hash) {
		return fmt.Errorf("state hash is different: %X vs %X", a.Hash, b.Hash)
	}
	if !bytes.Equal(a.BlockHash, b.BlockHash) {
		return fmt.Errorf("block hash is different: %X vs %X", a.BlockHash, b.BlockHash)
	}
	return nil
}

func (x *InputRecord) IsValid() error {
	if x == nil {
		return ErrInputRecordIsNil
	}
	if x.Version != 1 {
		return ErrInvalidVersion(x)
	}
	if x.Hash == nil {
		return ErrHashIsNil
	}
	if x.BlockHash == nil {
		return ErrBlockHashIsNil
	}
	if x.PreviousHash == nil {
		return ErrPreviousHashIsNil
	}
	if x.SummaryValue == nil {
		return ErrSummaryValueIsNil
	}
	if x.Timestamp == 0 {
		return errors.New("timestamp is unassigned")
	}
	sameSH := bytes.Equal(x.PreviousHash, x.Hash)
	if sameSH != isZeroHash(x.BlockHash) {
		if sameSH {
			return errors.New("state hash didn't change but block hash is not 0H")
		}
		return errors.New("block hash is 0H but state hash changed")
	}
	return nil
}

func (x *InputRecord) AddToHasher(hasher abhash.Hasher) {
	hasher.Write(x)
}

func (x *InputRecord) Bytes() []byte {
	bs, err := x.MarshalCBOR()
	if err != nil {
		panic(fmt.Errorf("failed to marshal input record: %w", err))
	}
	return bs
}

// NewRepeatIR - creates new repeat IR from current IR
func (x *InputRecord) NewRepeatIR() *InputRecord {
	return &InputRecord{
		Version:         1,
		PreviousHash:    bytes.Clone(x.PreviousHash),
		Hash:            bytes.Clone(x.Hash),
		BlockHash:       bytes.Clone(x.BlockHash),
		SummaryValue:    bytes.Clone(x.SummaryValue),
		RoundNumber:     x.RoundNumber,
		Epoch:           x.Epoch,
		Timestamp:       x.Timestamp,
		SumOfEarnedFees: x.SumOfEarnedFees,
	}
}

func (x *InputRecord) String() string {
	if x == nil {
		return "input record is nil"
	}
	return fmt.Sprintf("H: %X H': %X Bh: %X round: %d epoch: %d fees: %d summary: %X",
		x.Hash, x.PreviousHash, x.BlockHash, x.RoundNumber, x.Epoch, x.SumOfEarnedFees, x.SummaryValue)
}

func (x *InputRecord) GetVersion() ABVersion {
	if x != nil && x.Version > 0 {
		return x.Version
	}
	return 1
}

func (x *InputRecord) MarshalCBOR() ([]byte, error) {
	type alias InputRecord
	if x.Version == 0 {
		x.Version = x.GetVersion()
	}
	return Cbor.MarshalTaggedValue(InputRecordTag, (*alias)(x))
}

func (x *InputRecord) UnmarshalCBOR(data []byte) error {
	type alias InputRecord
	if err := Cbor.UnmarshalTaggedValue(InputRecordTag, data, (*alias)(x)); err != nil {
		return err
	}
	return EnsureVersion(x, x.Version, 1)
}
