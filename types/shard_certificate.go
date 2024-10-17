package types

import (
	"crypto"
	"fmt"
	"slices"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
)

type ShardTreeCertificate struct {
	_             struct{} `cbor:",toarray"`
	Shard         ShardID
	SiblingHashes [][]byte
}

func (cert ShardTreeCertificate) IsValid() error {
	if cnt := uint(len(cert.SiblingHashes)); cnt != cert.Shard.Length() {
		return fmt.Errorf("shard ID is %d bits but got %d sibling hashes", cert.Shard.Length(), cnt)
	}
	return nil
}

/*
ComputeCertificateHash implements the "Compute Shard Tree Certificate" algorithm.
Input:

	IR - input record of the shard
	TRHash - hash of the TechnicalRecord

Output: Root hash
*/
func (cert ShardTreeCertificate) ComputeCertificateHash(IR *InputRecord, TRHash []byte, algo crypto.Hash) ([]byte, error) {
	h := abhash.New(algo.New())
	h.Write(IR)
	h.Write(TRHash)
	rootHash, err := h.Sum()
	if err != nil {
		return nil, fmt.Errorf("calculating initial root hash: %w", err)
	}

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
		if rootHash, err = h.Sum(); err != nil {
			return nil, err
		}

		if bitIdx++; bitIdx == 8 {
			byteIdx--
			bitIdx = 0
		}
	}
	return rootHash, nil
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
	err := scheme.IsValid()
	if err != nil {
		return nil, fmt.Errorf("invalid sharding scheme: %w", err)
	}

	tree := ShardTree{}
	h := abhash.New(algo.New())
	for _, v := range states {
		h.Reset()
		h.Write(v.IR)
		h.Write(v.TRHash)
		if tree[v.Shard.Key()], err = h.Sum(); err != nil {
			return nil, fmt.Errorf("calculating hash for shard %s: %w", v.Shard, err)
		}
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
		if _, err = tree.generate(algo, ShardID{}); err != nil {
			return nil, fmt.Errorf("generating shard tree: %w", err)
		}
	}
	return tree, nil
}

type ShardTree map[string][]byte // ShardID.Key -> hash(IR, TRh)

/*
generate generates non-leaf nodes of the tree. This may be called only
when all the "leaf nodes" have been created as otherwise it would cause
infinite recursion.
*/
func (tree ShardTree) generate(algo crypto.Hash, id ShardID) (shardHash []byte, err error) {
	shardKey := id.Key()
	if dh, ok := tree[shardKey]; ok {
		return dh, nil
	}

	h := abhash.New(algo.New())
	id0, id1 := id.Split()

	if shardHash, err = tree.generate(algo, id0); err != nil {
		return nil, err
	}
	h.Write(shardHash)

	if shardHash, err = tree.generate(algo, id1); err != nil {
		return nil, err
	}
	h.Write(shardHash)

	shardHash, err = h.Sum()
	tree[shardKey] = shardHash
	return shardHash, err
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
		bits[byteIdx] ^= 1 << bitIdx
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
