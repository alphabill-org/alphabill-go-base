package fc

import (
	"crypto"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/hash"
)

/*
PrndSh returns function which generates pseudo-random byte sequence based on the input.
Meant to be used as unit identifier generator in PDR.ComposeUnitID.
Subsequent calls return the same value.
*/
func PrndSh(ownerPredicate []byte, timeout uint64) func(buf []byte) error {
	return func(buf []byte) error {
		unitPart, err := hash.HashValues(crypto.SHA256, ownerPredicate, timeout)
		if err != nil {
			return fmt.Errorf("generating fee credit record unit part: %w", err)
		}
		if n := copy(buf, unitPart); n != len(buf) {
			return fmt.Errorf("requested %d bytes but got %d", len(buf), n)
		}
		return nil
	}
}
