package types

import (
	"errors"
	"fmt"
	"time"

	"github.com/alphabill-org/alphabill-go-base/crypto"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

// GenesisTime min timestamp Thursday, April 20, 2023 6:11:24 AM GMT+00:00
// Epoch (or Unix time or POSIX time or Unix timestamp) is the number of seconds that have elapsed since January 1, 1970 (midnight UTC/GMT)
const GenesisTime uint64 = 1681971084

var (
	ErrUnicitySealIsNil          = errors.New("unicity seal is nil")
	ErrSignerIsNil               = errors.New("signer is nil")
	ErrUnicitySealHashIsNil      = errors.New("hash is nil")
	ErrInvalidRootRound          = errors.New("invalid root round number")
	ErrUnicitySealSignatureIsNil = errors.New("no signatures")
	ErrRootValidatorInfoMissing  = errors.New("root node info is missing")
	ErrInvalidTimestamp          = errors.New("invalid timestamp")
)

type SignatureMap = map[string]hex.Bytes

type UnicitySeal struct {
	_                    struct{}     `cbor:",toarray"`
	Version              ABVersion    `json:"version"`
	NetworkID            NetworkID    `json:"network"`
	RootChainRoundNumber uint64       `json:"rootChainRoundNumber"`
	Epoch                uint64       `json:"epoch"`        // Root Chain Epoch number
	Timestamp            uint64       `json:"timestamp"`    // Round creation time (wall clock value specified and verified by the Root Chain)
	PreviousHash         hex.Bytes    `json:"previousHash"` // Root hash of previous round’s Unicity Tree
	Hash                 hex.Bytes    `json:"hash"`         // Root hash of the Unicity Tree
	Signatures           SignatureMap `json:"signatures"`
}

// NewTimestamp - returns timestamp in seconds from epoch
func NewTimestamp() uint64 {
	// Epoch in seconds
	return uint64(time.Now().Unix())
}

func (x *UnicitySeal) GetVersion() ABVersion {
	if x != nil && x.Version > 0 {
		return x.Version
	}
	return 1
}

func (x *UnicitySeal) IsValid() error {
	if x == nil {
		return ErrUnicitySealIsNil
	}
	if x.Hash == nil {
		return ErrUnicitySealHashIsNil
	}
	if x.RootChainRoundNumber < 1 {
		return ErrInvalidRootRound
	}
	if x.Timestamp < GenesisTime {
		return ErrInvalidTimestamp
	}
	if len(x.Signatures) == 0 {
		return ErrUnicitySealSignatureIsNil
	}
	// when there is invalid signature the Verify should
	// fail but we can do simple sanity checks here too
	if _, ok := x.Signatures[""]; ok {
		return errors.New("signature without signer ID")
	}
	for k, v := range x.Signatures {
		if len(v) == 0 {
			return fmt.Errorf("empty signature for %q", k)
		}
	}
	return nil
}

// SigBytes - serialize everything except signatures (used for sign and verify)
func (x UnicitySeal) SigBytes() ([]byte, error) {
	x.Signatures = nil
	return x.MarshalCBOR()
}

func (x *UnicitySeal) Sign(id string, signer crypto.Signer) error {
	if signer == nil {
		return ErrSignerIsNil
	}
	bs, err := x.SigBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal unicity seal: %w", err)
	}
	sig, err := signer.SignBytes(bs)
	if err != nil {
		return fmt.Errorf("sign failed, %w", err)
	}
	// initiate signatures
	if x.Signatures == nil {
		x.Signatures = make(SignatureMap)
	}
	x.Signatures[id] = sig
	return nil
}

func (x *UnicitySeal) Verify(tb RootTrustBase) error {
	if tb == nil {
		return ErrRootValidatorInfoMissing
	}
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid unicity seal: %w", err)
	}
	bs, err := x.SigBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal unicity seal: %w", err)
	}
	if err := tb.VerifyQuorumSignatures(bs, x.Signatures); err != nil {
		return fmt.Errorf("verifying signatures: %w", err)
	}
	return nil
}

// AddToHasher - add all UC data including signature bytes for hash calculation
func (x *UnicitySeal) AddToHasher(hasher abhash.Hasher) {
	hasher.Write(x)
}

func (x *UnicitySeal) MarshalCBOR() ([]byte, error) {
	type alias UnicitySeal
	if x.Version == 0 {
		x.Version = x.GetVersion()
	}
	return Cbor.MarshalTaggedValue(UnicitySealTag, (*alias)(x))
}

func (x *UnicitySeal) UnmarshalCBOR(b []byte) (err error) {
	var arr []any
	if x.Version, arr, err = parseTaggedCBOR(b, UnicitySealTag); err != nil {
		return fmt.Errorf("unmarshaling UnicitySeal: %w", err)
	}
	if x.Version != 1 || len(arr) != 8 {
		return fmt.Errorf("unsupported UnicitySeal encoding, version %d with %d fields", x.Version, len(arr))
	}

	if id, ok := arr[1].(uint64); ok {
		x.NetworkID = NetworkID(id)
	} else {
		return fmt.Errorf("invalid network ID, expected uint64 got %T", arr[1])
	}

	var ok bool
	if x.RootChainRoundNumber, ok = arr[2].(uint64); !ok {
		return fmt.Errorf("invalid root round number, expected uint64 got %T", arr[2])
	}

	if x.Epoch, ok = arr[3].(uint64); !ok {
		return fmt.Errorf("invalid epoch, expected uint64 got %T", arr[3])
	}

	if x.Timestamp, ok = arr[4].(uint64); !ok {
		return fmt.Errorf("invalid timestamp, expected uint64 got %T", arr[4])
	}

	if x.PreviousHash, ok = arr[5].([]byte); !ok && arr[5] != nil {
		return fmt.Errorf("invalid previous hash, expected byte slice got %T", arr[5])
	}

	if x.Hash, ok = arr[6].([]byte); !ok && arr[6] != nil {
		return fmt.Errorf("invalid hash, expected byte slice got %T", arr[6])
	}

	if sigs, ok := arr[7].(map[any]any); ok {
		sigMap := make(SignatureMap, len(sigs))
		for k, v := range sigs {
			key, ok := k.(string)
			if !ok {
				return fmt.Errorf("invalid signer ID type: %T", k)
			}
			if sigMap[key], ok = v.([]byte); !ok {
				return fmt.Errorf("invalid signature type: %T", v)
			}
		}
		x.Signatures = sigMap
	} else if arr[7] != nil {
		return fmt.Errorf("unicity seal: invalid signatures, expected map, got %T", arr[7])
	}
	return nil
}
