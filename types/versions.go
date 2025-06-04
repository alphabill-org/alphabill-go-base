package types

import (
	"errors"
	"fmt"
)

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
	RootTrustBaseTag
	UnicityTreeCertificateTag
	TransactionRecordTag
	TransactionOrderTag
	RootPartitionBlockDataTag
	RootPartitionRoundInfoTag
)

func ErrInvalidVersion(s Versioned) error {
	// since s.GetVersion() might return a default value instead of an actual one, no need to print it
	return fmt.Errorf("invalid version (type %T)", s)
}

func EnsureVersion(data Versioned, actual, expected ABVersion) error {
	if data.GetVersion() != expected {
		return fmt.Errorf("invalid version (type %T), expected %d, got %d", data, expected, actual)
	}
	return nil
}

func parseTaggedCBOR(b []byte, objID ABTag) (ABVersion, []any, error) {
	tag, arr, err := Cbor.UnmarshalTagged(b)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to unmarshal as tagged CBOR: %w", err)
	}
	if tag != objID {
		return 0, nil, fmt.Errorf("expected tag %d, got %d", objID, tag)
	}
	if len(arr) == 0 {
		return 0, nil, errors.New("empty data slice")
	}
	if version, ok := arr[0].(uint64); ok {
		return ABVersion(version), arr, nil /* #nosec its unlikely that version exceeds uint32 */
	}
	return 0, nil, fmt.Errorf("expected version number to be uint64, got: %#v", arr[0])
}
