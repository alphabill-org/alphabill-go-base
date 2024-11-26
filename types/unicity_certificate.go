package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var ErrUnicityCertificateIsNil = errors.New("unicity certificate is nil")

type UnicityCertificate struct {
	_                      struct{}                `cbor:",toarray"`
	Version                ABVersion               `json:"version"`
	InputRecord            *InputRecord            `json:"inputRecord"`
	TRHash                 hex.Bytes               `json:"trHash"` // hash of the TechnicalRecord
	ShardTreeCertificate   ShardTreeCertificate    `json:"shardTreeCertificate"`
	UnicityTreeCertificate *UnicityTreeCertificate `json:"unicityTreeCertificate"`
	UnicitySeal            *UnicitySeal            `json:"unicitySeal"`
}

func (x *UnicityCertificate) IsValid(algorithm crypto.Hash, partitionID PartitionID, systemDescriptionHash []byte) error {
	if x == nil {
		return ErrUnicityCertificateIsNil
	}
	if x.Version != 1 {
		return ErrInvalidVersion(x)
	}
	if err := x.InputRecord.IsValid(); err != nil {
		return fmt.Errorf("input record error: %w", err)
	}
	if n := len(x.TRHash); n != 32 {
		return fmt.Errorf("invalid TRHash: expected 32 bytes, got %d bytes", n)
	}
	if err := x.UnicityTreeCertificate.IsValid(partitionID, systemDescriptionHash); err != nil {
		return fmt.Errorf("unicity tree certificate validation failed: %w", err)
	}
	if err := x.UnicitySeal.IsValid(); err != nil {
		return fmt.Errorf("unicity seal error: %w", err)
	}
	if err := x.ShardTreeCertificate.IsValid(); err != nil {
		return fmt.Errorf("invalid shard tree certificate: %w", err)
	}

	return nil
}

func (x *UnicityCertificate) Verify(tb RootTrustBase, algorithm crypto.Hash, partitionID PartitionID, systemDescriptionHash []byte) error {
	if err := x.IsValid(algorithm, partitionID, systemDescriptionHash); err != nil {
		return fmt.Errorf("invalid unicity certificate: %w", err)
	}

	strh, err := x.ShardTreeCertificate.ComputeCertificateHash(x.InputRecord, x.TRHash, algorithm)
	if err != nil {
		return err
	}
	treeRoot := x.UnicityTreeCertificate.EvalAuthPath(strh, algorithm)
	rootHash := x.UnicitySeal.Hash
	if !bytes.Equal(treeRoot, rootHash) {
		return fmt.Errorf("unicity seal hash %X does not match with the root hash of the unicity tree %X", rootHash, treeRoot)
	}

	if err := x.UnicitySeal.Verify(tb); err != nil {
		return fmt.Errorf("verifying unicity seal: %w", err)
	}
	return nil
}

func (x *UnicityCertificate) Hash(hash crypto.Hash) ([]byte, error) {
	hasher := abhash.New(hash.New())
	hasher.Write(x)
	return hasher.Sum()
}

func (x *UnicityCertificate) GetStateHash() []byte {
	if x != nil && x.InputRecord != nil {
		return x.InputRecord.Hash
	}
	return nil
}

func (x *UnicityCertificate) GetPreviousStateHash() []byte {
	if x != nil && x.InputRecord != nil {
		return x.InputRecord.PreviousHash
	}
	return nil
}

func (x *UnicityCertificate) GetRoundNumber() uint64 {
	if x != nil && x.InputRecord != nil {
		return x.InputRecord.RoundNumber
	}
	return 0
}

func (x *UnicityCertificate) GetRootRoundNumber() uint64 {
	if x != nil && x.UnicitySeal != nil {
		return x.UnicitySeal.RootChainRoundNumber
	}
	return 0
}

func (x *UnicityCertificate) GetFeeSum() uint64 {
	if x != nil && x.InputRecord != nil {
		return x.InputRecord.SumOfEarnedFees
	}
	return 0
}

func (x *UnicityCertificate) GetSummaryValue() []byte {
	if x != nil && x.InputRecord != nil {
		return x.InputRecord.SummaryValue
	}
	return nil
}

// CheckNonEquivocatingCertificates checks if provided certificates are equivocating
// NB! order is important, also it is assumed that validity of both UCs is checked before
// The algorithm is based on Yellowpaper: "Algorithm 6 Checking two UC-s for equivocation"
func CheckNonEquivocatingCertificates(prevUC, newUC *UnicityCertificate) error {
	if newUC == nil {
		return ErrUCIsNil
	}
	if prevUC == nil {
		return ErrLastUCIsNil
	}
	// verify order, check both partition round and root round
	if newUC.GetRootRoundNumber() < prevUC.GetRootRoundNumber() {
		return fmt.Errorf("new certificate is from older root round %v than previous certificate %v",
			newUC.UnicitySeal.RootChainRoundNumber, prevUC.UnicitySeal.RootChainRoundNumber)
	}
	if newUC.GetRoundNumber() < prevUC.GetRoundNumber() {
		return fmt.Errorf("new certificate is from older partition round %v than previous certificate %v",
			newUC.InputRecord.RoundNumber, prevUC.InputRecord.RoundNumber)
	}
	// 1. uc.IR.n = uc′.IR.n - if the partition round number is the same then input records must also match
	if newUC.GetRoundNumber() == prevUC.GetRoundNumber() {
		newIrBytes, err := newUC.InputRecord.Bytes()
		if err != nil {
			return fmt.Errorf("new certificate input record bytes: %w", err)
		}
		prevIrBytes, err := prevUC.InputRecord.Bytes()
		if err != nil {
			return fmt.Errorf("previous certificate input record bytes: %w", err)
		}
		if !bytes.Equal(newIrBytes, prevIrBytes) {
			return fmt.Errorf("equivocating UC, different input records for same partition round %v", newUC.GetRoundNumber())
		}
		// it's a Repeat UC
		return nil
	}
	// 2. not a repeat UC, then it must extend from previous state if certificates are from consecutive rounds,
	// if it is not from consecutive rounds then it is simply not possible to make any conclusions
	if newUC.GetRoundNumber() == prevUC.GetRoundNumber()+1 &&
		!bytes.Equal(newUC.InputRecord.PreviousHash, prevUC.InputRecord.Hash) {
		return fmt.Errorf("new certificate does not extend previous state hash")
	}
	// bridge 0H blocks
	// 5. uc.IR.h′ = uc.IR.h and uc.IR.h = uc.IR.h' -> extends last known state and new state does not change,
	// then new block must be empty
	if bytes.Equal(newUC.InputRecord.PreviousHash, prevUC.InputRecord.Hash) &&
		bytes.Equal(newUC.InputRecord.Hash, newUC.InputRecord.PreviousHash) {
		// then new block must not be empty
		if !isZeroHash(newUC.InputRecord.BlockHash) {
			return fmt.Errorf("new UC extends state hash, new state hash does not change, but block is not empty")
		}
	}
	// 6. uc.IR.h′ = uc'.IR.h and uc.IR.h = uc'.IR.h -> previous state hash is equal and new state is not equal,
	// then new block must be empty
	if bytes.Equal(newUC.InputRecord.PreviousHash, prevUC.InputRecord.Hash) &&
		!bytes.Equal(newUC.InputRecord.Hash, newUC.InputRecord.PreviousHash) {
		// then new block must be empty
		if isZeroHash(newUC.InputRecord.BlockHash) {
			return fmt.Errorf("new UC extends state hash, new state hash changes, but block is empty")
		}
	}
	// 7. non-empty block hash can only repeat in repeat UC
	if !isZeroHash(newUC.InputRecord.BlockHash) && bytes.Equal(newUC.InputRecord.BlockHash, prevUC.InputRecord.BlockHash) {
		return fmt.Errorf("new certificate repeats previous block hash")
	}
	return nil
}

func (x *UnicityCertificate) IsSuccessor(prevUC *UnicityCertificate) bool {
	return bytes.Equal(x.GetPreviousStateHash(), prevUC.GetStateHash())
}

func (x *UnicityCertificate) IsDuplicate(prevUC *UnicityCertificate) bool {
	return x.GetRootRoundNumber() == prevUC.GetRootRoundNumber()
}

func (x *UnicityCertificate) IsRepeat(prevUC *UnicityCertificate) (bool, error) {
	return isRepeat(prevUC, x)
}

// isRepeat - check if newUC is a repeat of previous UC.
// Everything else is the same except root round number may be bigger
func isRepeat(prevUC, newUC *UnicityCertificate) (bool, error) {
	eq, err := EqualIR(prevUC.InputRecord, newUC.InputRecord)
	if err != nil {
		return false, err
	}
	return eq && prevUC.UnicitySeal.RootChainRoundNumber < newUC.UnicitySeal.RootChainRoundNumber, nil
}

func (x *UnicityCertificate) GetVersion() ABVersion {
	if x != nil && x.Version > 0 {
		return x.Version
	}
	return 1
}

func (x *UnicityCertificate) MarshalCBOR() ([]byte, error) {
	type alias UnicityCertificate
	if x.Version == 0 {
		x.Version = x.GetVersion()
	}
	return Cbor.MarshalTaggedValue(UnicityCertificateTag, (*alias)(x))
}

func (x *UnicityCertificate) UnmarshalCBOR(data []byte) error {
	type alias UnicityCertificate
	if err := Cbor.UnmarshalTaggedValue(UnicityCertificateTag, data, (*alias)(x)); err != nil {
		return err
	}
	return EnsureVersion(x, x.Version, 1)
}
