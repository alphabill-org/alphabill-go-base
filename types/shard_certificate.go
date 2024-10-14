package types

import (
	"crypto"
	"fmt"
	"slices"
)

type ShardTreeCertificate struct {
	_             struct{} `cbor:",toarray"`
	Shard         ShardID
	SiblingHashes [][]byte
}

func (cert *ShardTreeCertificate) IsValid() error {
	if cnt := uint(len(cert.SiblingHashes)); cnt != cert.Shard.Length() {
		return fmt.Errorf("shard ID is %d bits but got %d sibling hashes", cert.Shard.Length(), cnt)
	}
	return nil
}

/*
ComputeCertificate implements the "Compute Shard Tree Certificate" algorithm.
Input:

	IR - input record of the shard
	TRHash - hash of the TechnicalRecord

Output: Root hash
*/
func (cert ShardTreeCertificate) ComputeCertificate(IR *InputRecord, TRHash []byte, algo crypto.Hash) []byte {
	h := algo.New()
	h.Write(IR.Bytes())
	h.Write(TRHash)
	rootHash := h.Sum(nil)

	bits := cert.Shard.bits
	byteIdx, bitIdx := cert.Shard.length/8, cert.Shard.length%8
	if bitIdx == 0 {
		byteIdx--
	} else {
		bitIdx = 8 - bitIdx
	}

	for _, sibHash := range cert.SiblingHashes {
		h.Reset()
		if bits[byteIdx]&(1<<bitIdx) == 0 {
			h.Write(rootHash)
			h.Write(sibHash)
		} else {
			h.Write(sibHash)
			h.Write(rootHash)
		}
		rootHash = h.Sum(nil)

		if bitIdx++; bitIdx == 8 {
			byteIdx--
			bitIdx = 0
		}
	}
	return rootHash
}

/*
ShardTreeInput is source data for leaf node in a shard tree
*/
type ShardTreeInput struct {
	Shard  ShardID
	IR     *InputRecord
	TRHash []byte // hash of TechnicalRecord
}

/*
"states" must contain record for each shard in the "scheme".
*/
func CreateShardTree(scheme ShardingScheme, states []ShardTreeInput, algo crypto.Hash) (ShardTree, error) {
	// this might be quite expensive check! Most of the places which create the tree should have
	// valid scheme (ie already validated) so make it callers responsibility and remove from here?
	if err := scheme.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid sharding scheme: %w", err)
	}

	tree := ShardTree{}
	h := algo.New()
	for _, v := range states {
		h.Reset()
		h.Write(v.IR.Bytes())
		h.Write(v.TRHash)
		tree[v.Shard.Key()] = h.Sum(nil)
	}

	// we now must have leaf in the tree for each shard in the scheme
	cnt := 0
	for id := range scheme.All() {
		if _, ok := tree[id.Key()]; !ok {
			return nil, fmt.Errorf("missing input for shard %q", id)
		}
		cnt++
	}
	if n := len(states); n != cnt {
		return nil, fmt.Errorf("scheme has %d shards but got input with %d items", cnt, n)
	}

	if cnt > 1 {
		tree.generate(algo, ShardID{})
	}
	return tree, nil
}

type ShardTree map[string][]byte // ShardID.Key -> hash(IR, TRh)

/*
generate generates non-leaf nodes of the tree. This may be called only
when all the "leaf nodes" have been created as otherwise it would cause
infinite recursion.
*/
func (tree ShardTree) generate(algo crypto.Hash, id ShardID) []byte {
	shardKey := id.Key()
	if dh, ok := tree[shardKey]; ok {
		return dh
	}

	id0, id1 := id.Split()
	h := algo.New()
	h.Write(tree.generate(algo, id0))
	h.Write(tree.generate(algo, id1))
	dh := h.Sum(nil)
	tree[shardKey] = dh
	return dh
}

var rootHashKey = ShardID{}.Key()

func (tree ShardTree) RootHash() []byte { return tree[rootHashKey] }

func (tree ShardTree) siblingHashes(shardID ShardID) [][]byte {
	// clone the shard ID so we do not mess with the original
	bits := slices.Clone(shardID.bits)
	id := ShardID{bits: bits, length: shardID.length}

	byteIdx, bitIdx := id.length/8, id.length%8
	if bitIdx == 0 {
		byteIdx--
	} else {
		bitIdx = 8 - bitIdx
	}

	r := make([][]byte, 0, id.length)
	for ; id.length > 0; id.length-- {
		bits[byteIdx] ^= (1 << bitIdx)
		r = append(r, tree[id.Key()])
		if bitIdx++; bitIdx == 8 {
			byteIdx--
			bitIdx = 0
		}
	}
	return r
}

/*
Certificate returns Shard Tree Certificate for the shard.
*/
func (tree ShardTree) Certificate(shardID ShardID) (ShardTreeCertificate, error) {
	if _, ok := tree[shardID.Key()]; !ok {
		return ShardTreeCertificate{}, fmt.Errorf("shard %q is not in the tree", shardID)
	}
	return ShardTreeCertificate{
		Shard:         shardID,
		SiblingHashes: tree.siblingHashes(shardID),
	}, nil
}
