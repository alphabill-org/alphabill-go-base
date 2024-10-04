package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/tree/mt"
)

var (
	ErrBlockIsNil = errors.New("block is nil")
)

type (
	// TxProof is a transaction execution proof.
	TxProof struct {
		_                  struct{} `cbor:",toarray"`
		Version            ABVersion
		BlockHeaderHash    []byte
		Chain              []*GenericChainItem
		UnicityCertificate TaggedCBOR
	}

	GenericChainItem struct {
		_    struct{} `cbor:",toarray"`
		Hash []byte
		Left bool
	}
)

func (p *TxProof) getUCv1() *UnicityCertificate {
	if p == nil || p.UnicityCertificate == nil {
		return nil
	}
	uc := &UnicityCertificate{}
	err := Cbor.Unmarshal(p.UnicityCertificate, uc)
	if err != nil {
		return nil // or panic?
	}
	return uc
}

func (p *TxProof) GetUnicityTreeSystemDescriptionHash() []byte {
	uc := p.getUCv1()
	if uc == nil || uc.UnicityTreeCertificate == nil {
		return nil
	}
	return uc.UnicityTreeCertificate.PartitionDescriptionHash
}

func NewTxProof(block *Block, txIndex int, algorithm crypto.Hash) (*TxProof, *TransactionRecord, error) {
	if block == nil {
		return nil, nil, ErrBlockIsNil
	}
	if txIndex < 0 || txIndex > len(block.Transactions)-1 {
		return nil, nil, fmt.Errorf("invalid tx index: %d", txIndex)
	}
	tree := mt.New(algorithm, block.Transactions)
	headerHash := block.HeaderHash(algorithm)
	chain, err := tree.GetMerklePath(txIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract merkle proof: %w", err)
	}
	items := make([]*GenericChainItem, len(chain))
	for i, item := range chain {
		items[i] = &GenericChainItem{
			Left: item.DirectionLeft,
			Hash: item.Hash,
		}
	}
	return &TxProof{
		Version:            1,
		BlockHeaderHash:    headerHash,
		Chain:              items,
		UnicityCertificate: block.UnicityCertificate,
	}, block.Transactions[txIndex], nil
}

func VerifyTxProof(proof *TxProof, txRecord *TransactionRecord, tb RootTrustBase, hashAlgorithm crypto.Hash) error {
	if proof == nil {
		return errors.New("tx proof is nil")
	}
	if txRecord == nil {
		return errors.New("tx record is nil")
	}
	if !txRecord.IsSuccessful() {
		return errors.New("transaction failed")
	}
	if txRecord.TransactionOrder == nil {
		return errors.New("tx order is nil")
	}
	merklePath := make([]*mt.PathItem, len(proof.Chain))
	for i, item := range proof.Chain {
		merklePath[i] = &mt.PathItem{
			Hash:          item.Hash,
			DirectionLeft: item.Left,
		}
	}
	// TODO ch 2.8.7: Verify Transaction Proof: VerifyTxProof: System description must be an input parameter
	sdrHash := proof.GetUnicityTreeSystemDescriptionHash()
	uc := proof.getUCv1()
	if err := uc.Verify(tb, hashAlgorithm, txRecord.TransactionOrder.SystemID(), sdrHash); err != nil {
		return fmt.Errorf("invalid unicity certificate: %w", err)
	}
	// h ← plain_tree_output(C, H(P))
	rootHash := mt.EvalMerklePath(merklePath, txRecord, hashAlgorithm)
	hasher := hashAlgorithm.New()
	hasher.Write(proof.BlockHeaderHash)
	hasher.Write(uc.InputRecord.PreviousHash)
	hasher.Write(uc.InputRecord.Hash)
	hasher.Write(rootHash)
	//h ← H(h_h,h)
	blockHash := hasher.Sum(nil)

	//UC.IR.hB = h
	if !bytes.Equal(blockHash, uc.InputRecord.BlockHash) {
		return fmt.Errorf("proof block hash does not match to block hash in unicity certificate")
	}
	return nil
}

func (p *TxProof) GetVersion() ABVersion {
	if p != nil && p.Version > 0 {
		return p.Version
	}
	return 1
}

func (p *TxProof) MarshalCBOR() ([]byte, error) {
	type alias TxProof
	if p.Version == 0 {
		p.Version = p.GetVersion()
	}
	return Cbor.MarshalTaggedValue(TxProofTag, (*alias)(p))
}

func (p *TxProof) UnmarshalCBOR(data []byte) error {
	type alias TxProof
	return Cbor.UnmarshalTaggedValue(TxProofTag, data, (*alias)(p))
}
