package evm

import (
	"math/big"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/ethereum/go-ethereum/common"
)

type (
	CallEVMRequest struct {
		_     struct{} `cbor:",toarray"`
		From  []byte
		To    []byte
		Data  []byte
		Value *big.Int
		Gas   uint64
	}

	CallEVMResponse struct {
		_                 struct{} `cbor:",toarray"`
		ProcessingDetails *ProcessingDetails
	}

	ProcessingDetails struct {
		_            struct{} `cbor:",toarray"`
		ErrorDetails string
		ReturnData   []byte
		ContractAddr common.Address
		Logs         []*LogEntry
	}

	LogEntry struct {
		_       struct{} `cbor:",toarray"`
		Address common.Address
		Topics  []common.Hash
		Data    []byte
	}
)

func (d *ProcessingDetails) Bytes() ([]byte, error) {
	return types.Cbor.Marshal(d)
}
