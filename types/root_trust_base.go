package types

import (
	"cmp"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"sync"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

type (
	RootTrustBase interface {
		GetNetworkID() NetworkID
		VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) error
		VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error)
		GetQuorumThreshold() uint64
		GetMaxFaultyNodes() uint64
		GetRootNodes() []*NodeInfo
	}

	RootTrustBaseV1 struct {
		_                 struct{}             `cbor:",toarray"`
		Version           ABVersion            `json:"version"`
		NetworkID         NetworkID            `json:"networkId"`
		Epoch             uint64               `json:"epoch"`             // current epoch number
		EpochStartRound   uint64               `json:"epochStartRound"`   // root chain round number when the epoch begins
		RootNodes         []*NodeInfo          `json:"rootNodes"`         // list of all root nodes for the current epoch
		QuorumThreshold   uint64               `json:"quorumThreshold"`   // amount of alpha required to reach consensus, currently each node gets equal amount of voting power i.e. +1 for each node
		StateHash         hex.Bytes            `json:"stateHash"`         // unicity tree root hash
		ChangeRecordHash  hex.Bytes            `json:"changeRecordHash"`  // epoch change request hash
		PreviousEntryHash hex.Bytes            `json:"previousEntryHash"` // previous trust base entry hash
		Signatures        map[string]hex.Bytes `json:"signatures"`        // signatures of previous epoch validators, over all fields except for the signatures fields itself
	}

	NodeInfo struct {
		_      struct{}  `cbor:",toarray"`
		NodeID string    `json:"nodeId"` // node identifier
		SigKey hex.Bytes `json:"sigKey"` // signing key of the node
		Stake  uint64    `json:"stake"`  // amount of staked alpha for this node

		// cached signature verifier; private fields are ignored in JSON and CBOR encodings
		sigVerifier     abcrypto.Verifier
		sigVerifierInit sync.Once
	}

	Option func(c *trustBaseConf)

	trustBaseConf struct {
		quorumThreshold uint64
	}
)

// NewTrustBaseGenesis creates new unsigned root trust base with default parameters.
func NewTrustBaseGenesis(networkID NetworkID, rootNodes []*NodeInfo, opts ...Option) (*RootTrustBaseV1, error) {
	if len(rootNodes) == 0 {
		return nil, errors.New("nodes list is empty")
	}

	// init config
	c := &trustBaseConf{}
	for _, opt := range opts {
		opt(c)
	}

	// Sort rootNodes by NodeID, so that we have a consistent order in every
	// implementation/encoding and we can perform binary search on them.
	slices.SortFunc(rootNodes, func(a, b *NodeInfo) int {
		return cmp.Compare(a.NodeID, b.NodeID)
	})

	// calculate quorum threshold
	var totalStake uint64
	for _, n := range rootNodes {
		totalStake += n.Stake
	}
	minStake := totalStake*2/3 + 1

	if c.quorumThreshold == 0 {
		c.quorumThreshold = minStake // set quorum threshold to minimum if no threshold was configured
	}
	if c.quorumThreshold < minStake {
		return nil, fmt.Errorf("quorum threshold must be at least '2/3+1' (min threshold %d got %d)", minStake, c.quorumThreshold)
	}
	if c.quorumThreshold > totalStake {
		return nil, fmt.Errorf("quorum threshold cannot exceed the total staked amount (max threshold %d got %d)", totalStake, c.quorumThreshold)
	}

	return &RootTrustBaseV1{
		Version:           1,
		NetworkID:         networkID,
		Epoch:             1,
		EpochStartRound:   1,
		RootNodes:         rootNodes,
		QuorumThreshold:   c.quorumThreshold,
		StateHash:         nil,
		ChangeRecordHash:  nil,
		PreviousEntryHash: nil,
		Signatures:        make(map[string]hex.Bytes),
	}, nil
}

// WithQuorumThreshold overrides the default 2/3+1 quorum threshold.
func WithQuorumThreshold(threshold uint64) Option {
	return func(c *trustBaseConf) {
		c.quorumThreshold = threshold
	}
}

// IsValid validates that all fields are correctly set and public keys are correct.
func (n *NodeInfo) IsValid() error {
	if n == nil {
		return errors.New("node info is empty")
	}
	if n.NodeID == "" {
		return errors.New("node identifier is empty")
	}
	// until proper staking is implemented require that all nodes do have equal stake
	// and thus equal vote when determining quorum
	if n.Stake != 1 {
		return errors.New("node must have stake == 1")
	}
	if len(n.SigKey) == 0 {
		return errors.New("signing key is empty")
	}
	if _, err := abcrypto.NewVerifierSecp256k1(n.SigKey); err != nil {
		return fmt.Errorf("signing key is invalid: %w", err)
	}
	return nil
}

func (n *NodeInfo) SigVerifier() (abcrypto.Verifier, error) {
	var err error
	n.sigVerifierInit.Do(func() {
		n.sigVerifier, err = abcrypto.NewVerifierSecp256k1(n.SigKey)
	})
	if err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}
	return n.sigVerifier, nil
}

// Sign signs the trust base entry, storing the signature to Signatures map.
func (r *RootTrustBaseV1) Sign(nodeID string, signer abcrypto.Signer) error {
	if nodeID == "" {
		return errors.New("node identifier is empty")
	}
	if signer == nil {
		return errors.New("signer is nil")
	}
	sb, err := r.SigBytes()
	if err != nil {
		return err
	}
	sig, err := signer.SignBytes(sb)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	r.Signatures[nodeID] = sig
	return nil
}

// Hash hashes the entire structure including the signatures.
func (r *RootTrustBaseV1) Hash(hashAlgo crypto.Hash) ([]byte, error) {
	hasher := abhash.New(hashAlgo.New())
	hasher.Write(r)
	return hasher.Sum()
}

// SigBytes serializes all fields expect for the signatures field.
func (r RootTrustBaseV1) SigBytes() ([]byte, error) {
	r.Signatures = nil
	bs, err := r.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal root trust base: %w", err)
	}
	return bs, nil
}

// VerifyQuorumSignatures verifies that the data is signed by enough root nodes so that quorum is reached,
// returns error if quorum is not reached.
func (r *RootTrustBaseV1) VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) error {
	// verify all signatures, calculate quorum
	var quorum uint64
	for nodeID, sig := range signatures {
		if stake, err := r.VerifySignature(data, sig, nodeID); err == nil {
			quorum += stake
		}
	}
	if quorum >= r.QuorumThreshold {
		return nil
	}
	return fmt.Errorf("quorum not reached, signed_votes=%d quorum_threshold=%d", quorum, r.QuorumThreshold)
}

// VerifySignature verifies that the data is signed by the given root validator,
// returns the validator's stake if it is signed.
func (r *RootTrustBaseV1) VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error) {
	verifierNode := r.getRootNode(nodeID)
	if verifierNode == nil {
		return 0, fmt.Errorf("author '%s' is not part of the trust base", nodeID)
	}
	verifier, err := verifierNode.SigVerifier()
	if err != nil {
		return 0, fmt.Errorf("failed to get signature verifier for nodeID=%s: %w", nodeID, err)
	}
	if err := verifier.VerifyBytes(sig, data); err != nil {
		return 0, fmt.Errorf("verify bytes failed: %w", err)
	}
	return verifierNode.Stake, nil
}

// GetQuorumThreshold returns the quorum threshold for the latest trust base entry.
func (r *RootTrustBaseV1) GetQuorumThreshold() uint64 {
	return r.QuorumThreshold
}

// GetMaxFaultyNodes returns max allowed faulty nodes, only works if one node == one vote.
func (r *RootTrustBaseV1) GetMaxFaultyNodes() uint64 {
	return uint64(len(r.RootNodes)) - r.QuorumThreshold
}

func (r *RootTrustBaseV1) GetRootNodes() []*NodeInfo {
	return r.RootNodes
}

func (r *RootTrustBaseV1) GetVersion() ABVersion {
	if r == nil || r.Version == 0 {
		return 1
	}
	return r.Version
}

func (r *RootTrustBaseV1) GetNetworkID() NetworkID {
	return r.NetworkID
}

func (r *RootTrustBaseV1) MarshalCBOR() ([]byte, error) {
	type alias RootTrustBaseV1
	if r.Version == 0 {
		r.Version = r.GetVersion()
	}
	return Cbor.MarshalTaggedValue(RootTrustBaseTag, (*alias)(r))
}

func (r *RootTrustBaseV1) UnmarshalCBOR(data []byte) error {
	type alias RootTrustBaseV1
	if err := Cbor.UnmarshalTaggedValue(RootTrustBaseTag, data, (*alias)(r)); err != nil {
		return fmt.Errorf("failed to unmarshal root trust base: %w", err)
	}
	return EnsureVersion(r, r.Version, 1)
}

func (r *RootTrustBaseV1) getRootNode(nodeID string) *NodeInfo {
	idx, found := slices.BinarySearchFunc(r.RootNodes, nodeID, func(nodeInfo *NodeInfo, nodeID string) int {
		return cmp.Compare(nodeInfo.NodeID, nodeID)
	})
	if found {
		return r.RootNodes[idx]
	}
	return nil
}
