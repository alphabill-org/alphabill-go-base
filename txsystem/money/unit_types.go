package money

import (
	"fmt"

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
	BillUnitType            = []byte{1}
	FeeCreditRecordUnitType = []byte{16}
)

func NewBillID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, BillUnitType)
}

func NewFeeCreditRecordID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, FeeCreditRecordUnitType)
}

func NewFeeCreditRecordIDFromPublicKey(shardPart, pubKey []byte, latestAdditionTime uint64) (types.UnitID, error) {
	ownerPredicate := templates.NewP2pkh256BytesFromKey(pubKey)
	return NewFeeCreditRecordIDFromOwnerPredicate(shardPart, ownerPredicate, latestAdditionTime)
}

func NewFeeCreditRecordIDFromPublicKeyHash(shardPart, pubKeyHash []byte, latestAdditionTime uint64) (types.UnitID, error) {
	ownerPredicate := templates.NewP2pkh256BytesFromKeyHash(pubKeyHash)
	return NewFeeCreditRecordIDFromOwnerPredicate(shardPart, ownerPredicate, latestAdditionTime)
}

func NewFeeCreditRecordIDFromOwnerPredicate(shardPart []byte, ownerPredicate []byte, latestAdditionTime uint64) (types.UnitID, error) {
	unitPart, err := fc.NewFeeCreditRecordUnitPart(ownerPredicate, latestAdditionTime)
	if err != nil {
		return nil, fmt.Errorf("failed to create fee credit record unit part: %w", err)
	}
	return NewFeeCreditRecordID(shardPart, unitPart), nil
}
