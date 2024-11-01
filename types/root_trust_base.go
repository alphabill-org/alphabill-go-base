package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"sort"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
	"github.com/alphabill-org/alphabill-go-base/util"
)

type (
	RootTrustBase interface {
		VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) (error, []error)
		VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error)
		GetQuorumThreshold() uint64
		GetMaxFaultyNodes() uint64
	}

	RootTrustBaseV0 struct {
		_                 struct{}             `cbor:",toarray"`
		Epoch             uint64               `json:"epoch"`             // current epoch number
		EpochStartRound   uint64               `json:"epochStartRound"`   // root chain round number when the epoch begins
		RootNodes         map[string]*NodeInfo `json:"rootNodes"`         // list of all root nodes for the current epoch
		QuorumThreshold   uint64               `json:"quorumThreshold"`   // amount of alpha required to reach consensus, currently each node gets equal amount of voting power i.e. +1 for each node
		StateHash         hex.Bytes            `json:"stateHash"`         // unicity tree root hash
		ChangeRecordHash  hex.Bytes            `json:"changeRecordHash"`  // epoch change request hash
		PreviousEntryHash hex.Bytes            `json:"previousEntryHash"` // previous trust base entry hash
		Signatures        map[string]hex.Bytes `json:"signatures"`        // signatures of previous epoch validators, over all fields except for the signatures fields itself
	}

	NodeInfo struct {
		_         struct{}          `cbor:",toarray"`
		NodeID    string            `json:"nodeId"`    // node identifier derived from node's encryption public key
		PublicKey hex.Bytes         `json:"publicKey"` // the trust base signing public key
		Stake     uint64            `json:"stake"`     // amount of staked alpha for this node, currently unused as each nodes get equal votes regardless of stake
		verifier  abcrypto.Verifier // cached verifier, should always be filled in constructor; private field is ignored in json and cbor
	}

	Option func(c *trustBaseConf)

	trustBaseConf struct {
		quorumThreshold uint64
	}
)

// NewTrustBaseGenesis creates new unsigned root trust base with default genesis parameters.
func NewTrustBaseGenesis(nodes []*NodeInfo, unicityTreeRootHash []byte, opts ...Option) (*RootTrustBaseV0, error) {
	if len(nodes) == 0 {
		return nil, errors.New("nodes list is empty")
	}
	if len(unicityTreeRootHash) == 0 {
		return nil, errors.New("unicity tree root hash is empty")
	}

	// init config
	c := &trustBaseConf{}
	for _, opt := range opts {
		opt(c)
	}

	// calculate quorum threshold
	if c.quorumThreshold == 0 {
		var stakedSum uint64
		for _, n := range nodes {
			stakedSum += n.Stake
		}
		c.quorumThreshold = stakedSum*2/3 + 1
	}
	if c.quorumThreshold == 0 {
		return nil, errors.New("calculated quorum threshold cannot be zero")
	}

	// create node info list
	rootNodes, err := newRootNodes(nodes)
	if err != nil {
		return nil, err
	}
	return &RootTrustBaseV0{
		Epoch:             1,
		EpochStartRound:   1,
		RootNodes:         rootNodes,
		QuorumThreshold:   c.quorumThreshold,
		StateHash:         unicityTreeRootHash,
		ChangeRecordHash:  nil,
		PreviousEntryHash: nil,
		Signatures:        make(map[string]hex.Bytes),
	}, nil
}

// NewTrustBaseFromFile loads trust base from file and caches verifiers.
func NewTrustBaseFromFile(trustBaseFile string) (*RootTrustBaseV0, error) {
	trustBase, err := util.ReadJsonFile(trustBaseFile, &RootTrustBaseV0{})
	if err != nil {
		return nil, fmt.Errorf("loading root trust base file %s: %w", trustBaseFile, err)
	}
	// cache verifiers
	for _, rn := range trustBase.RootNodes {
		verifier, err := abcrypto.NewVerifierSecp256k1(rn.PublicKey)
		if err != nil {
			return nil, err
		}
		rn.verifier = verifier
	}
	return trustBase, nil
}

// NewNodeInfo creates new NodeInfo, caching the verifier in private field.
func NewNodeInfo(nodeID string, stake uint64, verifier abcrypto.Verifier) *NodeInfo {
	key, err := verifier.MarshalPublicKey()
	if err != nil {
		panic("failed to marshal abcrypto.Verifier to public key bytes")
	}
	return &NodeInfo{
		NodeID:    nodeID,
		PublicKey: key,
		Stake:     stake,
		verifier:  verifier,
	}
}

// WithQuorumThreshold overrides the default 2/3+1 quorum threshold.
func WithQuorumThreshold(threshold uint64) Option {
	return func(c *trustBaseConf) {
		c.quorumThreshold = threshold
	}
}

// Bytes serializes all fields.
func (n *NodeInfo) Bytes() []byte {
	var b bytes.Buffer
	b.Write([]byte(n.NodeID))
	b.Write(n.PublicKey)
	b.Write(util.Uint64ToBytes(n.Stake))
	return b.Bytes()
}

// Sign signs the trust base entry, storing the signature to Signatures map.
func (r *RootTrustBaseV0) Sign(nodeID string, signer abcrypto.Signer) error {
	if nodeID == "" {
		return errors.New("node identifier is empty")
	}
	if signer == nil {
		return errors.New("signer is nil")
	}
	sig, err := signer.SignBytes(r.SigBytes())
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	r.Signatures[nodeID] = sig
	return nil
}

// Hash hashes the entire structure including the signatures.
func (r *RootTrustBaseV0) Hash(hashAlgo crypto.Hash) []byte {
	hasher := hashAlgo.New()
	hasher.Write(r.SigBytes())

	// hash signatures in deterministic order
	var keys []string
	for nodeID := range r.Signatures {
		keys = append(keys, nodeID)
	}
	sort.Strings(keys)
	for _, nodeID := range keys {
		hasher.Write(r.Signatures[nodeID])
	}
	return hasher.Sum(nil)
}

// SigBytes serializes all fields expect for the signatures field.
func (r *RootTrustBaseV0) SigBytes() []byte {
	var b bytes.Buffer
	b.Write(util.Uint64ToBytes(r.Epoch))
	b.Write(util.Uint64ToBytes(r.EpochStartRound))

	// serialize node info in alphabetic order by node identifiers
	var keys []string
	for nodeID := range r.RootNodes {
		keys = append(keys, nodeID)
	}
	sort.Strings(keys)
	for _, nodeID := range keys {
		b.Write(r.RootNodes[nodeID].Bytes())
	}

	b.Write(util.Uint64ToBytes(r.QuorumThreshold))
	b.Write(r.StateHash)
	b.Write(r.ChangeRecordHash)
	b.Write(r.PreviousEntryHash)
	return b.Bytes()
}

// VerifyQuorumSignatures verifies that the data is signed by enough root nodes so that quorum is reached,
// returns error if quorum is not reached, also returns list of any signature verification errors,
// regardless if quorum is reached or not.
func (r *RootTrustBaseV0) VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) (error, []error) {
	// verify all signatures, calculate quorum
	var quorum uint64
	var verificationErrors []error
	for nodeID, sig := range signatures {
		stake, err := r.VerifySignature(data, sig, nodeID)
		if err != nil {
			verificationErrors = append(verificationErrors, err)
		} else {
			quorum += stake
		}
	}
	if quorum >= r.QuorumThreshold {
		return nil, verificationErrors
	}
	return fmt.Errorf("quorum not reached, signed_votes=%d quorum_threshold=%d", quorum, r.QuorumThreshold), verificationErrors
}

// VerifySignature verifies that the data is signed by the given root validator,
// returns the validator's stake if it is signed.
func (r *RootTrustBaseV0) VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error) {
	verifierNode, f := r.RootNodes[nodeID]
	if !f {
		return 0, fmt.Errorf("author '%s' is not part of the trust base", nodeID)
	}
	verifier := verifierNode.verifier
	if verifier == nil {
		return 0, fmt.Errorf("cached verifier not found for nodeID=%s", nodeID)
	}
	if err := verifier.VerifyBytes(sig, data); err != nil {
		return 0, fmt.Errorf("verify bytes failed: %w", err)
	}
	return verifierNode.Stake, nil
}

// GetVerifiers returns the cached verifiers.
func (r *RootTrustBaseV0) GetVerifiers() (map[string]abcrypto.Verifier, error) {
	verifiers := make(map[string]abcrypto.Verifier, len(r.RootNodes))
	for nodeID, rn := range r.RootNodes {
		verifiers[nodeID] = rn.verifier
	}
	return verifiers, nil
}

// GetQuorumThreshold returns the quorum threshold for the latest trust base entry.
func (r *RootTrustBaseV0) GetQuorumThreshold() uint64 {
	return r.QuorumThreshold
}

// GetMaxFaultyNodes returns max allowed faulty nodes, only works if one node == one vote.
func (r *RootTrustBaseV0) GetMaxFaultyNodes() uint64 {
	return uint64(len(r.RootNodes)) - r.QuorumThreshold
}

// newRootNodes converts []*NodeInfo to map[string]*NodeInfo
func newRootNodes(nodes []*NodeInfo) (map[string]*NodeInfo, error) {
	nodeMap := map[string]*NodeInfo{}
	for _, nodeInfo := range nodes {
		nodeMap[nodeInfo.NodeID] = nodeInfo
	}
	return nodeMap, nil
}
