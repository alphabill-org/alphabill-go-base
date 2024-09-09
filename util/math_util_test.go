package util

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeAddOverflow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a      uint64
		b      uint64
		result uint64
		ok     bool
	}{
		{1, 1, 2, true},
		{math.MaxUint64, 1, 0, false},
		{math.MaxUint64, 0, math.MaxUint64, true},
		{math.MaxUint64 - 1, 1, math.MaxUint64, true},
	}
	for _, tt := range cases {
		result, ok := SafeAdd(tt.a, tt.b)
		require.Equal(t, tt.ok, ok)
		require.Equal(t, tt.result, result)
	}
}

func TestSafeSubUnderflow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a      uint64
		b      uint64
		result uint64
		ok     bool
	}{
		{2, 1, 1, true},
		{math.MaxUint64, math.MaxUint64, 0, true},
		{math.MaxUint64 - 1, math.MaxUint64, 0, false},
		{1, 2, 0, false},
	}
	for _, tt := range cases {
		result, ok := SafeSub(tt.a, tt.b)
		require.Equal(t, tt.ok, ok)
		require.Equal(t, tt.result, result)
	}
}
