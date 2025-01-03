package mt

import (
	"crypto"
	"errors"
	"fmt"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var ErrIndexOutOfBounds = errors.New("merkle tree data index out of bounds")

type (
	MerkleTree struct {
		root       *node
		dataLength int // number of leaves
	}

	Data interface {
		Hash(hashAlgorithm crypto.Hash) ([]byte, error)
	}

	// PathItem helper struct for proof extraction, contains Hash and Direction from parent node
	PathItem struct {
		_             struct{}  `cbor:",toarray"`
		DirectionLeft bool      `json:"directionLeft"` // true - left from parent, false - right from parent
		Hash          hex.Bytes `json:"hash"`
	}

	node struct {
		left  *node
		right *node
		hash  []byte
	}
)

// New creates a new canonical Merkle Tree.
func New[T Data](hashAlgorithm crypto.Hash, data []T) (*MerkleTree, error) {
	if len(data) == 0 {
		return &MerkleTree{root: nil, dataLength: 0}, nil
	}
	tree, err := createMerkleTree(data, hashAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create merkle tree: %w", err)
	}
	return &MerkleTree{root: tree, dataLength: len(data)}, nil
}

// EvalMerklePath returns root hash calculated from the given leaf and path items
func EvalMerklePath(merklePath []*PathItem, leaf Data, hashAlgorithm crypto.Hash) ([]byte, error) {
	h, err := leaf.Hash(hashAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to hash leaf: %w", err)
	}
	hasher := abhash.New(hashAlgorithm.New())
	for _, item := range merklePath {
		if item.DirectionLeft {
			hasher.Write(h)
			hasher.Write(item.Hash)
		} else {
			hasher.Write(item.Hash)
			hasher.Write(h)
		}
		h, err = hasher.Sum()
		if err != nil {
			return nil, fmt.Errorf("failed to calculate hash: %w", err)
		}
		hasher.Reset()
	}
	return h, nil
}

// PlainTreeOutput calculates the output hash of the chain.
func PlainTreeOutput(merklePath []*PathItem, input []byte, hashAlgorithm crypto.Hash) ([]byte, error) {
	if len(merklePath) == 0 {
		return input, nil
	}
	hasher := abhash.New(hashAlgorithm.New())
	h := input
	var err error
	for _, item := range merklePath {
		if item.DirectionLeft {
			hasher.Write(h)
			hasher.Write(item.Hash)
		} else {
			hasher.Write(item.Hash)
			hasher.Write(h)
		}
		h, err = hasher.Sum()
		if err != nil {
			return nil, fmt.Errorf("failed to calculate hash: %w", err)
		}
		hasher.Reset()
	}
	return h, nil
}

// GetRootHash returns the root Hash of the Merkle Tree.
func (s *MerkleTree) GetRootHash() []byte {
	if s.root == nil {
		return nil
	}
	return s.root.hash
}

// GetMerklePath extracts the merkle path from the given leaf to root.
func (s *MerkleTree) GetMerklePath(leafIdx int) ([]*PathItem, error) {
	if leafIdx < 0 || leafIdx >= s.dataLength {
		return nil, ErrIndexOutOfBounds
	}

	var z []*PathItem
	curr := s.root
	b := 0
	m := s.dataLength

	// iteratively descending the tree
	for m > 1 {
		n := hibit(m - 1)
		if leafIdx < b+n { // target in the left sub-tree
			z = append([]*PathItem{{Hash: curr.right.hash, DirectionLeft: true}}, z...)
			curr = curr.left
			m = n
		} else { // target in the right sub-tree
			z = append([]*PathItem{{Hash: curr.left.hash, DirectionLeft: false}}, z...)
			curr = curr.right
			b = b + n
			m = m - n
		}
	}
	return z, nil
}

// PrettyPrint returns human readable string representation of the Merkle Tree.
func (s *MerkleTree) PrettyPrint() string {
	if s.root == nil {
		return "tree is empty"
	}
	out := ""
	s.output(s.root, "", false, &out)
	return out
}

func (s *MerkleTree) output(node *node, prefix string, isTail bool, str *string) {
	if node.right != nil {
		newPrefix := prefix
		if isTail {
			newPrefix += "│   "
		} else {
			newPrefix += "    "
		}
		s.output(node.right, newPrefix, false, str)
	}
	*str += prefix
	if isTail {
		*str += "└── "
	} else {
		*str += "┌── "
	}
	*str += fmt.Sprintf("%X\n", node.hash)
	if node.left != nil {
		newPrefix := prefix
		if isTail {
			newPrefix += "    "
		} else {
			newPrefix += "│   "
		}
		s.output(node.left, newPrefix, true, str)
	}
}

func createMerkleTree[T Data](data []T, hashAlgorithm crypto.Hash) (*node, error) {
	if len(data) == 0 {
		return &node{hash: make([]byte, hashAlgorithm.Size())}, nil
	}
	if len(data) == 1 {
		h, err := data[0].Hash(hashAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to hash data: %w", err)
		}
		return &node{hash: h}, nil
	}
	n := hibit(len(data) - 1)
	left, err := createMerkleTree(data[:n], hashAlgorithm)
	if err != nil {
		return nil, err
	}
	right, err := createMerkleTree(data[n:], hashAlgorithm)
	if err != nil {
		return nil, err
	}

	h, err := abhash.HashValues(hashAlgorithm, left.hash, right.hash)
	if err != nil {
		return nil, fmt.Errorf("failed to hash child nodes: %w", err)
	}
	return &node{left: left, right: right, hash: h}, nil
}

// hibit floating-point-free equivalent of 2**math.floor(math.log(m, 2)),
// could be preferred for larger values of m to avoid rounding errors
func hibit(n int) int {
	if n < 0 {
		panic("hibit function input cannot be negative (merkle tree input data length cannot be zero)")
	}
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n - (n >> 1)
}
