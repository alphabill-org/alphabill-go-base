package money

import (
	"github.com/alphabill-org/alphabill-go-base/predicates/templates"
	"github.com/alphabill-org/alphabill-go-base/txsystem/fc"
	"github.com/alphabill-org/alphabill-go-base/types"
)

const (
	UnitIDLength   = UnitPartLength + TypePartLength
	UnitPartLength = 32
	TypePartLength = 1
)

var (
	BillUnitType            = []byte{0x00}
	FeeCreditRecordUnitType = []byte{0x0f}
)

func NewBillID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, BillUnitType)
}

func NewFeeCreditRecordID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, FeeCreditRecordUnitType)
}

func NewFeeCreditRecordIDFromPublicKey(shardPart, pubKey []byte, timeout uint64) types.UnitID {
	ownerPredicate := templates.NewP2pkh256BytesFromKey(pubKey)
	return NewFeeCreditRecordIDFromOwnerPredicate(shardPart, ownerPredicate, timeout)
}

func NewFeeCreditRecordIDFromPublicKeyHash(shardPart, pubKeyHash []byte, timeout uint64) types.UnitID {
	ownerPredicate := templates.NewP2pkh256BytesFromKeyHash(pubKeyHash)
	return NewFeeCreditRecordIDFromOwnerPredicate(shardPart, ownerPredicate, timeout)
}

func NewFeeCreditRecordIDFromOwnerPredicate(shardPart []byte, ownerPredicate []byte, timeout uint64) types.UnitID {
	unitPart := fc.NewFeeCreditRecordUnitPart(ownerPredicate, timeout)
	return NewFeeCreditRecordID(shardPart, unitPart)
}
