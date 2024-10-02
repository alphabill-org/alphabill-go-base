package types

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"sort"
	"time"

	"github.com/alphabill-org/alphabill-go-base/crypto"
	"github.com/alphabill-org/alphabill-go-base/util"
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

type SignatureMap map[string][]byte
type UnicitySeal struct {
	_                    struct{}     `cbor:",toarray"`
	Version              ABVersion    `json:"version,omitempty"`
	RootChainRoundNumber uint64       `json:"root_chain_round_number,omitempty"`
	Timestamp            uint64       `json:"timestamp,omitempty"`
	PreviousHash         []byte       `json:"previous_hash,omitempty"`
	Hash                 []byte       `json:"hash,omitempty"`
	Signatures           SignatureMap `json:"signatures,omitempty"`
}

// Signatures are serialized as alphabetically sorted CBOR array
type signaturesCBOR []*signature
type signature struct {
	_         struct{} `cbor:",toarray"`
	NodeID    string   `json:"node_id,omitempty"`
	Signature []byte   `json:"signature,omitempty"`
}

func (s SignatureMap) MarshalCBOR() ([]byte, error) {
	// shallow copy
	authors := make([]string, 0, len(s))
	for k := range s {
		authors = append(authors, k)
	}
	sort.Strings(authors)
	sCBOR := make(signaturesCBOR, len(s))
	for i, author := range authors {
		sCBOR[i] = &signature{NodeID: author, Signature: s[author]}
	}
	return Cbor.Marshal(sCBOR)
}

func (s *SignatureMap) UnmarshalCBOR(b []byte) error {
	var sCBOR signaturesCBOR
	if err := Cbor.Unmarshal(b, &sCBOR); err != nil {
		return fmt.Errorf("cbor unmarshal failed, %w", err)
	}
	sigMap := make(SignatureMap)
	for _, sig := range sCBOR {
		sigMap[sig.NodeID] = sig.Signature
	}
	*s = sigMap
	return nil
}

func (s SignatureMap) AddToHasher(hasher hash.Hash) {
	if s == nil {
		return
	}
	authors := make([]string, 0, len(s))
	for k := range s {
		authors = append(authors, k)
	}
	sort.Strings(authors)
	for _, author := range authors {
		sig := s[author]
		hasher.Write([]byte(author))
		hasher.Write(sig)
	}
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

func (x *UnicitySeal) GetTag() ABTag {
	return UnicitySealTag
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
func (x *UnicitySeal) Bytes() []byte {
	var b bytes.Buffer
	b.Write(util.Uint32ToBytes(x.GetVersion()))
	b.Write(util.Uint64ToBytes(x.RootChainRoundNumber))
	b.Write(util.Uint64ToBytes(x.Timestamp))
	b.Write(x.PreviousHash)
	b.Write(x.Hash)
	return b.Bytes()
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
		return fmt.Errorf("unicity seal validation error: %w", err)
	}
	err, _ := tb.VerifyQuorumSignatures(x.Bytes(), x.Signatures)
	if err != nil {
		return err
	}
	return nil
}

// AddToHasher - add all UC data including signature bytes for hash calculation
func (x *UnicitySeal) AddToHasher(hasher hash.Hash) {
	hasher.Write(x.Bytes())
	x.Signatures.AddToHasher(hasher)
}

func (x *UnicitySeal) MarshalCBOR() ([]byte, error) {
	sigs, err := x.Signatures.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	return Cbor.MarshalTagged(x.GetTag(), x.GetVersion(), x.RootChainRoundNumber, x.Timestamp, x.PreviousHash, x.Hash, sigs)
}

func (x *UnicitySeal) UnmarshalCBOR(b []byte) error {
	tag, arr, err := Cbor.UnmarshalTagged(b)
	if err != nil {
		return err
	}
	if tag != x.GetTag() {
		return fmt.Errorf("invalid tag %d, expected %d", tag, x.GetTag())
	}
	// with forward compatibility, newer versions can be added, thus must not fail here
	//if version != x.GetVersion() {
	//	return fmt.Errorf("invalid version %d, expected %d", version, x.GetVersion())
	//}
	if len(arr) < 6 {
		return fmt.Errorf("invalid array length: %d", len(arr))
	}
	if version, ok := arr[0].(uint64); ok {
		if version == 0 {
			return fmt.Errorf("invalid version number: %d", version)
		}
		x.Version = ABVersion(version)
	} else {
		return errors.New("invalid version number")
	}
	if round, ok := arr[1].(uint64); ok {
		x.RootChainRoundNumber = round
	} else {
		return errors.New("invalid root round number")
	}
	if ts, ok := arr[2].(uint64); ok {
		x.Timestamp = ts
	} else {
		return errors.New("invalid timestamp")
	}
	if prevHash, ok := arr[3].([]byte); ok {
		x.PreviousHash = prevHash
	} else if prevHash != nil {
		return errors.New("invalid previous hash")
	}
	if h, ok := arr[4].([]byte); ok {
		x.Hash = h
	} else {
		return errors.New("invalid hash")
	}
	if sigs, ok := arr[5].([]byte); ok {
		var sigMap SignatureMap
		if err := sigMap.UnmarshalCBOR(sigs); err != nil {
			return err
		}
		x.Signatures = sigMap
	} else if sigs != nil {
		return errors.New("invalid signatures")
	}
	return nil
}
