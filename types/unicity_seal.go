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
	RootChainRoundNumber uint64       `json:"rootChainRoundNumber"`
	Timestamp            uint64       `json:"timestamp"`
	PreviousHash         hex.Bytes    `json:"previousHash"`
	Hash                 hex.Bytes    `json:"hash"`
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
	return nil
}

// Bytes - serialize everything except signatures (used for sign and verify)
func (x UnicitySeal) Bytes() []byte {
	x.Signatures = nil
	bs, err := x.MarshalCBOR()
	if err != nil {
		panic(fmt.Errorf("failed to marshal unicity seal: %w", err))
	}
	return bs
}

func (x *UnicitySeal) Sign(id string, signer crypto.Signer) error {
	if signer == nil {
		return ErrSignerIsNil
	}
	sig, err := signer.SignBytes(x.Bytes())
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
	if err, _ := tb.VerifyQuorumSignatures(x.Bytes(), x.Signatures); err != nil {
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

func (x *UnicitySeal) UnmarshalCBOR(b []byte) error {
	tag, arr, err := Cbor.UnmarshalTagged(b)
	if err != nil {
		return fmt.Errorf("failed to unmarshal unicity seal: %w", err)
	}
	if tag != UnicitySealTag {
		return fmt.Errorf("invalid tag %d, expected %d", tag, UnicitySealTag)
	}
	if len(arr) < 6 {
		return fmt.Errorf("unicity seal: invalid array length: %d", len(arr))
	}
	if version, ok := arr[0].(uint64); ok {
		if version != 1 {
			return fmt.Errorf("unicity seal: invalid version number: expected 1, got %d", version)
		}
		x.Version = ABVersion(version)
	} else {
		return fmt.Errorf("unicity seal: unexpected type of version: %+v", arr[0])
	}
	if round, ok := arr[1].(uint64); ok {
		x.RootChainRoundNumber = round
	} else {
		return fmt.Errorf("unicity seal: unexpected type of root round number: %+v", arr[1])
	}
	if ts, ok := arr[2].(uint64); ok {
		x.Timestamp = ts
	} else {
		return fmt.Errorf("unicity seal: unexpected type of timestamp: %+v", arr[2])
	}
	if prevHash, ok := arr[3].([]byte); ok || arr[3] == nil {
		x.PreviousHash = prevHash
	} else {
		return fmt.Errorf("unicity seal: invalid previous hash: %+v", arr[3])
	}
	if h, ok := arr[4].([]byte); ok || arr[4] == nil {
		x.Hash = h
	} else {
		return fmt.Errorf("unicity seal: invalid hash: %+v", arr[4])
	}
	if sigs, ok := arr[5].(map[any]any); ok {
		sigMap := make(SignatureMap)
		for k, v := range sigs {
			key, ok := k.(string)
			if !ok || key == "" {
				return fmt.Errorf("invalid key type: %T", k)
			}
			if value, ok := v.([]byte); ok {
				sigMap[key] = value
			} else {
				return fmt.Errorf("invalid value type: %T", v)
			}
		}
		x.Signatures = sigMap
	} else if arr[5] != nil {
		return fmt.Errorf("unicity seal: invalid signatures: %+v", arr[5])
	}
	return nil
}
