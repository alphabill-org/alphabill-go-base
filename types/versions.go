package types

type ABTag uint64
type ABVersion uint64

type Versioned interface {
	GetVersion() ABVersion
}

type Tagged interface {
	GetTag() ABTag
}

const (
	_ = iota + ABTag(1000)
	UnicitySealTag
)
