package util

import (
	"math/bits"
)

/*
AddUint64 adds a list of uint64s together, returning sum and a boolean indicator
if the sum is ok (ie didn't overflow).

Special cases:
  - if the list is empty the sum is zero and ok == true;
  - if there is just one element in the argument slice it's value will be
    returned as sum (and ok == true);

Use [SafeAdd] to add just two ints.
*/
func AddUint64(ns ...uint64) (uint64, bool) {
	if len(ns) == 0 {
		return 0, true
	}

	var carry uint64
	sum := ns[0]
	for _, v := range ns[1:] {
		if sum, carry = bits.Add64(sum, v, 0); carry != 0 {
			return 0, false
		}
	}

	return sum, true
}

/*
SafeAdd returns a+b and checks for overflow, the second return value is "ok", ie
it is "true" when the returned sum is valid and "false" in case of overflow.
*/
func SafeAdd(a, b uint64) (uint64, bool) {
	sum, carry := bits.Add64(a, b, 0)
	return sum, carry == 0
}

/*
SafeSub returns a-b and boolean indicating is the result ok (ie no underflow).
*/
func SafeSub(a, b uint64) (uint64, bool) {
	diff, borrow := bits.Sub64(a, b, 0)
	return diff, borrow == 0
}
