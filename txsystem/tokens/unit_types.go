package tokens

import (
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/predicates/templates"
	"github.com/alphabill-org/alphabill-go-base/txsystem/fc"
	"github.com/alphabill-org/alphabill-go-base/types"
)

const (
	FungibleTokenTypeUnitType    = 1
	NonFungibleTokenTypeUnitType = 2
	FungibleTokenUnitType        = 3
	NonFungibleTokenUnitType     = 4
	FeeCreditRecordUnitType      = 16
)

/*
GenerateUnitID generates unit ID for the transaction order (and assigns it to the txo.UnitID field).
ID is generated to be in the "shard" shard of the partition described by "pdr". If the "shard" is
empty shard ID then the unit ID is generated to be in a random shard.

The txo must have it's Type, Attributes and ClientMetadata fields assigned!
*/
func GenerateUnitID(txo *types.TransactionOrder, shard types.ShardID, pdr *types.PartitionDescriptionRecord) error {
	if pdr.NetworkID != txo.NetworkID {
		return fmt.Errorf("invalid network %d (expected %d)", txo.NetworkID, pdr.NetworkID)
	}
	if pdr.PartitionID != txo.PartitionID {
		return fmt.Errorf("invalid partition %d (expected %d)", txo.PartitionID, pdr.PartitionID)
	}
	if shard.Length() > 0 {
		if err := pdr.IsValidShard(shard); err != nil {
			return fmt.Errorf("invalid shard ID: %w", err)
		}
	}

	var unitType uint32
	switch txo.Type {
	case TransactionTypeDefineFT:
		unitType = FungibleTokenTypeUnitType
	case TransactionTypeDefineNFT:
		unitType = NonFungibleTokenTypeUnitType
	case TransactionTypeMintFT:
		unitType = FungibleTokenUnitType
	case TransactionTypeMintNFT:
		unitType = NonFungibleTokenUnitType
	default:
		return fmt.Errorf(`invalid tx type %#x - unit ID can be generated only for "mint" transactions`, txo.Type)
	}

	var err error
	if txo.UnitID, err = pdr.ComposeUnitID(shard, unitType, PrndSh(txo)); err != nil {
		return fmt.Errorf("creating unit ID: %w", err)
	}
	return nil
}

func NewUnitData(unitID types.UnitID, pdr *types.PartitionDescriptionRecord) (types.UnitData, error) {
	typeID, err := pdr.ExtractUnitType(unitID)
	if err != nil {
		return nil, fmt.Errorf("extracting type ID: %w", err)
	}

	switch typeID {
	case FungibleTokenTypeUnitType:
		return &FungibleTokenTypeData{}, nil
	case NonFungibleTokenTypeUnitType:
		return &NonFungibleTokenTypeData{}, nil
	case FungibleTokenUnitType:
		return &FungibleTokenData{}, nil
	case NonFungibleTokenUnitType:
		return &NonFungibleTokenData{}, nil
	case FeeCreditRecordUnitType:
		return &fc.FeeCreditRecord{}, nil
	}

	return nil, fmt.Errorf("unknown unit type in UnitID %s", unitID)
}

func NewFeeCreditRecordIDFromPublicKey(pdr *types.PartitionDescriptionRecord, shard types.ShardID, pubKey []byte, latestAdditionTime uint64) (types.UnitID, error) {
	ownerPredicate := templates.NewP2pkh256BytesFromKey(pubKey)
	return NewFeeCreditRecordIDFromOwnerPredicate(pdr, shard, ownerPredicate, latestAdditionTime)
}

func NewFeeCreditRecordIDFromPublicKeyHash(pdr *types.PartitionDescriptionRecord, shard types.ShardID, pubKeyHash []byte, latestAdditionTime uint64) (types.UnitID, error) {
	ownerPredicate := templates.NewP2pkh256BytesFromKeyHash(pubKeyHash)
	return NewFeeCreditRecordIDFromOwnerPredicate(pdr, shard, ownerPredicate, latestAdditionTime)
}

func NewFeeCreditRecordIDFromOwnerPredicate(pdr *types.PartitionDescriptionRecord, shard types.ShardID, ownerPredicate []byte, latestAdditionTime uint64) (types.UnitID, error) {
	return pdr.ComposeUnitID(shard, FeeCreditRecordUnitType, fc.PrndSh(ownerPredicate, latestAdditionTime))
}
