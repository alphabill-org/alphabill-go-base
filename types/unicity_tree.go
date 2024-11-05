package types

import (
	"bytes"
	"cmp"
	"crypto"
	"fmt"
	"slices"

	"github.com/alphabill-org/alphabill-go-base/tree/imt"
)

type UnicityTree struct {
	imt     *imt.Tree
	pdrhMap map[PartitionID][]byte
}

/*
NewUnicityTree creates a new unicity tree with given partitions.

NB! Sorts the "data" slice without making copy of it!
*/
func NewUnicityTree(hashAlgorithm crypto.Hash, data []*UnicityTreeData) (*UnicityTree, error) {
	// sort by partition id
	slices.SortFunc(data, func(a, b *UnicityTreeData) int {
		return cmp.Compare(a.Partition, b.Partition)
	})
	sdMap := make(map[PartitionID][]byte)
	leaves := make([]imt.LeafData, len(data))
	for i, d := range data {
		leaves[i] = d
		sdMap[d.Partition] = d.PDRHash
	}
	t, err := imt.New(hashAlgorithm, leaves)
	if err != nil {
		return nil, fmt.Errorf("creating index tree: %w", err)
	}
	return &UnicityTree{
		imt:     t,
		pdrhMap: sdMap,
	}, nil
}

func (u *UnicityTree) RootHash() []byte {
	return bytes.Clone(u.imt.GetRootHash())
}

// Certificate returns an unicity tree certificate for given system identifier.
func (u *UnicityTree) Certificate(partition PartitionID) (*UnicityTreeCertificate, error) {
	pdrh, found := u.pdrhMap[partition]
	if !found {
		return nil, fmt.Errorf("certificate for partition %s not found", partition)
	}
	path, err := u.imt.GetMerklePath(partition.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating index tree chain: %w", err)
	}
	return &UnicityTreeCertificate{
		Partition: partition,
		PDRHash:   pdrh,
		HashSteps: path[1:], // drop redundant first hash step; path is guaranteed to have size > 0
	}, nil
}
