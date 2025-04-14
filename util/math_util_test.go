package util

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddUint64(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		cases := []struct {
			input  []uint64
			result uint64
		}{
			{nil, 0},
			{[]uint64{}, 0},
			{[]uint64{1}, 1},
			{[]uint64{1, 2}, 3},
			{[]uint64{0, 0, 0}, 0},
			{[]uint64{0, 1, 0}, 1},
			{[]uint64{2, 1, 3}, 6},
			{[]uint64{math.MaxUint64, 0}, math.MaxUint64},
			{[]uint64{math.MaxUint64 - 2, 1, 1}, math.MaxUint64},
		}

		for x, tt := range cases {
			sum, ok := AddUint64(tt.input...)
			if !ok {
				t.Errorf("unexpected overflow for test case %d", x)
				continue
			}
			if sum != tt.result {
				t.Errorf("[%d] expected sum %d, got %d", x, tt.result, sum)
			}
		}
	})

	t.Run("overflow", func(t *testing.T) {
		cases := [][]uint64{
			{math.MaxUint64, 1},
			{math.MaxUint64, 1, 1},
			{1, math.MaxUint64},
			{1, 1, math.MaxUint64 - 1},
			{math.MaxUint64, math.MaxUint64, math.MaxUint64},
		}

		for x, tt := range cases {
			if sum, ok := AddUint64(tt...); ok {
				t.Errorf("expected overflow for test case %d, got %d", x, sum)
			}
		}
	})
}

func TestSafeAdd(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		cases := []struct {
			a      uint64
			b      uint64
			result uint64
		}{
			{0, 0, 0},
			{0, 1, 1},
			{1, 0, 1},
			{1, 1, 2},
			{math.MaxUint32, math.MaxUint32, 0x01_fffffffe},
			{math.MaxUint64, 0, math.MaxUint64},
			{0, math.MaxUint64, math.MaxUint64},
			{math.MaxUint64 - 1, 1, math.MaxUint64},
			{1, math.MaxUint64 - 1, math.MaxUint64},
		}

		for _, tt := range cases {
			result, ok := SafeAdd(tt.a, tt.b)
			if !ok {
				t.Errorf("unexpected overflow for %x + %x = %x", tt.a, tt.b, tt.result)
				continue
			}
			if result != tt.result {
				t.Errorf("%x + %x = %x (expected %x)", tt.a, tt.b, result, tt.result)
			}
		}
	})

	t.Run("overflow", func(t *testing.T) {
		cases := []struct {
			a uint64
			b uint64
		}{
			{math.MaxUint64, 1},
			{1, math.MaxUint64},
			{math.MaxUint64 - 1, 2},
			{math.MaxUint64, math.MaxUint64},
		}

		for _, tt := range cases {
			if result, ok := SafeAdd(tt.a, tt.b); ok {
				t.Errorf("expected overflow for %x + %x got %x", tt.a, tt.b, result)
			}
		}
	})
}

func TestSafeSub(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		cases := []struct {
			a      uint64
			b      uint64
			result uint64
		}{
			{0, 0, 0},
			{1, 1, 0},
			{2, 1, 1},
			{math.MaxUint64, 1, math.MaxUint64 - 1},
			{math.MaxUint64, math.MaxUint64 - 1, 1},
			{math.MaxUint64, math.MaxUint64, 0},
		}

		for _, tt := range cases {
			result, ok := SafeSub(tt.a, tt.b)
			if !ok {
				t.Errorf("unexpected underflow for %x - %x", tt.a, tt.b)
				continue
			}
			require.Equal(t, tt.result, result, "%x - %x = %x", tt.a, tt.b, result)
		}
	})

	t.Run("underflow", func(t *testing.T) {
		cases := []struct {
			a uint64
			b uint64
		}{
			{0, 1},
			{1, 2},
			{0, math.MaxUint64},
			{1, math.MaxUint64},
			{math.MaxUint64 - 1, math.MaxUint64},
		}

		for _, tt := range cases {
			if result, ok := SafeSub(tt.a, tt.b); ok {
				t.Errorf("expected underflow for %x - %x got %x", tt.a, tt.b, result)
			}
		}
	})
}
