package interface_uc_array_cbor_tags

type ABTag uint64

const (
	UC1Tag ABTag = 1001
	UC2Tag ABTag = 1002

	Block1Tag ABTag = 2001
)

type (
	Versioned interface {
		GetVersion() ABTag
	}
)
