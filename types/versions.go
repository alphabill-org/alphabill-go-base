package types

type ABVersion uint64

type Versioned interface {
	GetVersion() ABVersion
}

const (
	UnicitySealV1Tag ABVersion = 1001
)
