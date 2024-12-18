package money

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/alphabill-org/alphabill-go-base/predicates/templates"
	"github.com/alphabill-org/alphabill-go-base/txsystem/money"
	"github.com/alphabill-org/alphabill-go-base/types"
)

var testPDR = types.PartitionDescriptionRecord{
	Version:         1,
	PartitionTypeID: money.PartitionTypeID,
	NetworkID:       types.NetworkLocal,
	PartitionID:     money.DefaultPartitionID,
	UnitIDLen:       8 * 32,
	TypeIDLen:       8,
	T2Timeout:       1500 * time.Millisecond,
	FeeCreditBill: &types.FeeCreditBill{
		UnitID:         append(make(types.UnitID, 31), 2, money.BillUnitType),
		OwnerPredicate: templates.AlwaysTrueBytes(),
	},
}

/*
PDR returns copy of the PartitionDescriptionRecord used by the unit ID
generator functions in this package.

Prefer to create test specific PDR and use it's ComposeUnitID method!
*/
func PDR() types.PartitionDescriptionRecord {
	return testPDR
}

func NewBillID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, money.BillUnitType, Random)
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

func BillIDWithSuffix(t *testing.T, suffix byte, pdr *types.PartitionDescriptionRecord) types.UnitID {
	if pdr == nil {
		pdr = &testPDR
	}
	uid, err := pdr.ComposeUnitID(types.ShardID{}, money.BillUnitType, func(b []byte) error { b[len(b)-1] = suffix; return nil })
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

func NewFeeCreditRecordID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, money.FeeCreditRecordUnitType, Random)
	if err != nil {
		t.Fatal("failed to generate unit ID:", err)
	}
	return uid
}

/*
Random fills the buf with random bytes.
Meant to be used as argument for the unit ID generator.
*/
func Random(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}
