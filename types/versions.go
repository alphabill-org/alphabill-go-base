package types

import "fmt"

type ABTag = uint64
type ABVersion = uint32

// Versioned interface is used by the structs that require versioning.
// By our convention, the version is the first field of the struct with type ABVersion.
// Version must be greater than 0.
type Versioned interface {
	GetVersion() ABVersion
}

const (
	_ = iota + ABTag(1000)
	UnicitySealTag
	RootGenesisTag
	GenesisRootRecordTag
	ConsensusParamsTag
	GenesisPartitionRecordTag
	PartitionNodeTag
	UnicityCertificateTag
	InputRecordTag
	TxProofTag
	UnitStateProofTag
	PartitionDescriptionRecordTag
	BlockTag
)

func ErrInvalidVersion(s Versioned) error {
	// since s.GetVersion() might return a default value instead of an actual one, no need to print it
	return fmt.Errorf("invalid version (type %T)", s)
}
