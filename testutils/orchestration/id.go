package orchestration

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/alphabill-org/alphabill-go-base/txsystem/orchestration"
	"github.com/alphabill-org/alphabill-go-base/types"
)

var testPDR = types.PartitionDescriptionRecord{
	Version:         1,
	PartitionTypeID: orchestration.PartitionTypeID,
	NetworkID:       types.NetworkLocal,
	PartitionID:     orchestration.DefaultPartitionID,
	UnitIDLen:       8 * 32,
	TypeIDLen:       8,
	T2Timeout:       1500 * time.Millisecond,
}

/*
PDR returns copy of the PartitionDescriptionRecord used by the unit ID
generator functions in this package.

Prefer to create test specific PDR and use it's ComposeUnitID or
orchestration.GenerateUnitID method!
*/
func PDR() types.PartitionDescriptionRecord {
	return testPDR
}

/*
NewVarID return new Validator Assignment Record ID
*/
func NewVarID(t *testing.T) types.UnitID {
	uid, err := testPDR.ComposeUnitID(types.ShardID{}, orchestration.VarUnitType, Random)
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
