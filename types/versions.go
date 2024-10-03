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
)

func ErrInvalidVersion(s Versioned) error {
	return fmt.Errorf("invalid version %d (type %T)", s.GetVersion(), s)
}
