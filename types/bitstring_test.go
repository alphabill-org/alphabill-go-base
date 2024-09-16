package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_EncodeBitstring(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		// nil buf with zero length is encoded as end marker
		var in []byte
		buf := encodeBitstring(in, 0)
		require.Equal(t, []byte{0b1000_0000}, buf)

		// but nil buf with non-zero length panics
		require.Panics(t, func() { encodeBitstring(in, 5) })
	})

	t.Run("selected values", func(t *testing.T) {
		// some selected edge cases
		testCases := []struct {
			in  []byte // input
			len uint   // number of bits from "in" to consider
			out []byte // expected output
		}{
			{in: []byte{}, len: 0, out: []byte{128}},                         // empty input -> end marker
			{in: []byte{0}, len: 1, out: []byte{0b0100_0000}},                // one bit, off
			{in: []byte{128}, len: 1, out: []byte{0b1100_0000}},              // one bit, on
			{in: []byte{0}, len: 7, out: []byte{1}},                          // 7 bits off
			{in: []byte{0b1111_1110}, len: 7, out: []byte{0xFF}},             // 7 bits on
			{in: []byte{0}, len: 8, out: []byte{0, 128}},                     // 8 bits off
			{in: []byte{0xFF}, len: 8, out: []byte{0xFF, 128}},               // 8 bits on
			{in: []byte{0, 0}, len: 9, out: []byte{0, 0b0100_0000}},          // 9 bits off
			{in: []byte{0xFF, 0xFF}, len: 9, out: []byte{0xFF, 0b1100_0000}}, // 9 bits on
		}

		for x, tc := range testCases {
			buf := encodeBitstring(tc.in, tc.len)
			if !bytes.Equal(buf, tc.out) {
				t.Errorf("[%d] expected %x got %x", x, tc.out, buf)
			}
		}
	})

	t.Run("roundtrip", func(t *testing.T) {
		// encode-decode bits, output must equal the original input
		encDec := func(bits []byte, cnt uint) {
			out, l, err := decodeBitstring(encodeBitstring(bits, cnt))
			require.NoError(t, err)
			require.EqualValues(t, cnt, l)
			require.Equal(t, bits, out)
		}

		for n := 1; n < 20; n++ {
			byteCnt := n / 8
			if n%8 != 0 {
				byteCnt++
			}
			// fresh slice, all bytes are zero
			bits := make([]byte, byteCnt)
			encDec(bits, uint(n))

			// set all bits to "1"
			for x := range bits {
				bits[x] = 0xFF
			}
			if n%8 != 0 {
				bits[len(bits)-1] <<= (8 - n%8)
			}
			encDec(bits, uint(n))
		}
	})
}

func Test_DecodeBitstring(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		var in []byte
		buf, l, err := decodeBitstring(in)
		require.EqualError(t, err, `invalid bit string encoding: empty input`)
		require.Zero(t, l)
		require.Zero(t, buf)
	})

	t.Run("last byte is not end marker", func(t *testing.T) {
		in := []byte{0}
		buf, l, err := decodeBitstring(in)
		require.EqualError(t, err, `invalid bit string encoding: last byte doesn't contain end marker`)
		require.Zero(t, l)
		require.Zero(t, buf)

		in = []byte{0xFF, 0}
		buf, l, err = decodeBitstring(in)
		require.EqualError(t, err, `invalid bit string encoding: last byte doesn't contain end marker`)
		require.Zero(t, l)
		require.Zero(t, buf)
	})

	t.Run("valid input", func(t *testing.T) {
		testCases := []struct {
			in  []byte // encoded bitstring, ie with end marker
			out []byte // decoded bits, ie without end marker
			len uint   // number of (decoded) bits
		}{
			{in: []byte{0b1000_0000}, out: []byte{}, len: 0},            // empty
			{in: []byte{0b0100_0000}, out: []byte{0}, len: 1},           // single zero bit
			{in: []byte{0b1100_0000}, out: []byte{128}, len: 1},         // single one bit
			{in: []byte{0b1000_0011}, out: []byte{0b1000_0010}, len: 7}, // first and last bit set
			{in: []byte{0b0001_0001}, out: []byte{0b0001_0000}, len: 7}, // middle bit is set
			{in: []byte{0, 0b1000_0000}, out: []byte{0}, len: 8},
			{in: []byte{1, 0b1000_0000}, out: []byte{1}, len: 8},
			{in: []byte{128, 0b1000_0000}, out: []byte{128}, len: 8},
			{in: []byte{0xFF, 0b1000_0000}, out: []byte{0xFF}, len: 8},
			{in: []byte{0b0001_0001, 0b1000_0000}, out: []byte{0b0001_0001}, len: 8},
			{in: []byte{0b0001_0001, 0b1100_0000}, out: []byte{0b0001_0001, 128}, len: 9}, // top bit of second byte is set
		}

		for x, tc := range testCases {
			buf, l, err := decodeBitstring(tc.in)
			require.NoError(t, err, "test case [%d]", x)
			require.EqualValues(t, tc.len, l, "test case [%d]", x)
			require.Equal(t, tc.out, buf, "test case [%d]", x)
		}
	})
}
