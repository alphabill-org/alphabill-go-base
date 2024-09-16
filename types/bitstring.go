package types

import (
	"errors"
	"math/bits"
)

/*
encodeBitstring adds "end marker" to the bit string of given length.
It returns new slice, the input slice is not modified.
If "bits" is not long enough for "length" bits function panics.

The bits "in use" in the partially used byte are high bits, ie bit string
of two bits is byte BBxx_xxxx where B marks bits in use. String of nine
bits would be two bytes [BBBB_BBBB, Bxxx_xxx] etc.
*/
func encodeBitstring(bits []byte, length uint) []byte {
	byteCnt, bitCnt := length/8, length%8
	bs := make([]byte, byteCnt+1)
	copy(bs, bits[:byteCnt])
	if bitCnt == 0 {
		bs[byteCnt] = 0b_1000_0000
	} else {
		// clear trailing bits
		v := bits[byteCnt] &^ (0xFF >> bitCnt)
		// add end marker
		bs[byteCnt] = v | (1 << (7 - bitCnt))
	}
	return bs
}

/*
decodeBitstring returns the input data slice (ie the same underlying array) where
the end marker is removed and number of "bits in use" in the returned slice.
*/
func decodeBitstring(data []byte) ([]byte, uint, error) {
	byteCnt := len(data) - 1
	if byteCnt < 0 {
		return nil, 0, errors.New("invalid bit string encoding: empty input")
	}

	switch zc := bits.TrailingZeros8(data[byteCnt]); zc {
	case 8:
		return nil, 0, errors.New("invalid bit string encoding: last byte doesn't contain end marker")
	case 7: // entire last byte is end marker
		return data[:byteCnt], uint(byteCnt * 8), nil
	default:
		data[byteCnt] ^= (1 << zc) // clear end marker
		return data, uint(byteCnt*8 + 7 - zc), nil
	}
}
