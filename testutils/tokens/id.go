package tokens

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/alphabill-org/alphabill-go-base/txsystem/tokens"
	"github.com/alphabill-org/alphabill-go-base/types"
)

var testPDR = types.PartitionDescriptionRecord{
	Version:         1,
	PartitionTypeID: tokens.PartitionTypeID,
	NetworkID:       types.NetworkTestNet,
	PartitionID:     tokens.DefaultPartitionID,
	UnitIDLen:       8 * 32,
	TypeIDLen:       8,
	T2Timeout:       1500 * time.Millisecond,
}

/*
PDR returns copy of the PartitionDescriptionRecord used by the unit ID
generator functions in this package.

Prefer to create test specific PDR and use it's ComposeUnitID method!
*/
func PDR() types.PartitionDescriptionRecord {
	return testPDR
}

/*
NewFungibleTokenTypeID generates "valid looking" Fungible Token Type unit ID.
Hardcoded Partition Description Record is used by this function.
Use in cases where PDR is not available, when PDR is available use it (and it's
ComposeUnitID method) to generate unit ID.
*/
func NewFungibleTokenTypeID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, tokens.FungibleTokenTypeUnitType, Random)
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

func NewFungibleTokenID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, tokens.FungibleTokenUnitType, Random)
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

func NewNonFungibleTokenTypeID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, tokens.NonFungibleTokenTypeUnitType, Random)
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

func NewNonFungibleTokenID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, tokens.NonFungibleTokenUnitType, Random)
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

func NewFeeCreditRecordID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, tokens.FeeCreditRecordUnitType, Random)
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

func Random(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}
