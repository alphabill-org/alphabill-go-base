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
	imt        *imt.Tree
	partitions map[PartitionID]struct{}
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
	partitions := make(map[PartitionID]struct{})
	leaves := make([]imt.LeafData, len(data))
	for i, d := range data {
		leaves[i] = d
		partitions[d.Partition] = struct{}{}
	}
	t, err := imt.New(hashAlgorithm, leaves)
	if err != nil {
		return nil, fmt.Errorf("creating index tree: %w", err)
	}
	return &UnicityTree{
		imt:        t,
		partitions: partitions,
	}, nil
}

func (u *UnicityTree) RootHash() []byte {
	return bytes.Clone(u.imt.GetRootHash())
}

// Certificate returns an unicity tree certificate for given partition identifier.
func (u *UnicityTree) Certificate(partitionID PartitionID) (*UnicityTreeCertificate, error) {
	if _, found := u.partitions[partitionID]; !found {
		return nil, fmt.Errorf("certificate for partition %s not found", partitionID)
	}
	pathItems, err := u.imt.GetMerklePath(partitionID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("creating index tree chain: %w", err)
	}
	// convert imt.PathItems to types.PathItem (possibly can be avoided if we generify the IMT?)
	path, err := NewPathItems(pathItems)
	if err != nil {
		return nil, fmt.Errorf("failed to create hash chain: %w", err)
	}
	return &UnicityTreeCertificate{
		Version:   1,
		Partition: partitionID,
		HashSteps: path[1:], // drop redundant first hash step; path is guaranteed to have size > 0
	}, nil
}

func NewPathItems(pathItems []*imt.PathItem) ([]*PathItem, error) {
	path := make([]*PathItem, 0, len(pathItems))
	for _, pathItem := range pathItems {
		p, err := NewPathItem(pathItem)
		if err != nil {
			return nil, err
		}
		path = append(path, p)
	}
	return path, nil
}

func NewPathItem(p *imt.PathItem) (*PathItem, error) {
	partitionID, err := BytesToPartitionID(p.Key)
	if err != nil {
		return nil, err
	}
	return &PathItem{
		Key:  partitionID,
		Hash: p.Hash,
	}, nil
}
