package tokens

import (
	"crypto/rand"
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
	FungibleTokenTypeUnitType    = []byte{1}
	NonFungibleTokenTypeUnitType = []byte{2}
	FungibleTokenUnitType        = []byte{3}
	NonFungibleTokenUnitType     = []byte{4}
	FeeCreditRecordUnitType      = []byte{16}
)

func NewFungibleTokenTypeID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, FungibleTokenTypeUnitType)
}

func NewFungibleTokenID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, FungibleTokenUnitType)
}

func NewNonFungibleTokenTypeID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, NonFungibleTokenTypeUnitType)
}

func NewNonFungibleTokenID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, NonFungibleTokenUnitType)
}

func NewFeeCreditRecordID(shardPart []byte, unitPart []byte) types.UnitID {
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, FeeCreditRecordUnitType)
}

func NewRandomFungibleTokenTypeID(shardPart []byte) (types.UnitID, error) {
	return newRandomUnitID(shardPart, FungibleTokenTypeUnitType)
}

func NewRandomFungibleTokenID(shardPart []byte) (types.UnitID, error) {
	return newRandomUnitID(shardPart, FungibleTokenUnitType)
}

func NewRandomNonFungibleTokenTypeID(shardPart []byte) (types.UnitID, error) {
	return newRandomUnitID(shardPart, NonFungibleTokenTypeUnitType)
}

func NewRandomNonFungibleTokenID(shardPart []byte) (types.UnitID, error) {
	return newRandomUnitID(shardPart, NonFungibleTokenUnitType)
}

func newRandomUnitID(shardPart []byte, typePart []byte) (types.UnitID, error) {
	unitPart := make([]byte, UnitPartLength)
	_, err := rand.Read(unitPart)
	if err != nil {
		return nil, err
	}
	return types.NewUnitID(UnitIDLength, shardPart, unitPart, typePart), nil
}

func NewUnitData(unitID types.UnitID) (types.UnitData, error) {
	if unitID.HasType(FungibleTokenTypeUnitType) {
		return &FungibleTokenTypeData{}, nil
	}
	if unitID.HasType(FungibleTokenUnitType) {
		return &FungibleTokenData{}, nil
	}
	if unitID.HasType(NonFungibleTokenTypeUnitType) {
		return &NonFungibleTokenTypeData{}, nil
	}
	if unitID.HasType(NonFungibleTokenUnitType) {
		return &NonFungibleTokenData{}, nil
	}
	if unitID.HasType(FeeCreditRecordUnitType) {
		return &fc.FeeCreditRecord{}, nil
	}
	return nil, fmt.Errorf("unknown unit type in UnitID %s", unitID)
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
