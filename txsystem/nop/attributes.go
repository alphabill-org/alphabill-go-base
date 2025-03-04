// Package nop implements a generic counter based "nop" transaction that is currently
// used by all transaction systems. The "nop operation may resolve the previous
// conditional (pending) transaction and its purpose is to resolve the state of
// pending transactions without doing anything else with the system's state. The
// exact behaviour of nop is specified separately in every transaction system.
// The NOP transaction does not change unit's owner and in unit data it only
// changes security-related fields e.g. the counter.
package nop

const (
	TransactionTypeNOP uint16 = 22
)

type (
	// Attributes is transaction of type "nop".
	// The NOP transaction is used by all transaction systems.
	Attributes struct {
		_ struct{} `cbor:",toarray"`

		Counter *uint64 // the target unit counter
	}
)
