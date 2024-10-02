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

// Tagged interface is used by the structs that are versioned and are serialized into CBOR bytes.
// Tag allows to identify the struct type when unmarshalling.
type Tagged interface {
	GetTag() ABTag
}

type TaggedVersioned interface {
	Tagged
	Versioned
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

func ErrInvalidVersion(s TaggedVersioned) error {
	return fmt.Errorf("invalid version %d (tag %d)", s.GetVersion(), s.GetTag())
}
