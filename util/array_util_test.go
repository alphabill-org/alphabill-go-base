package util

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ShuffleSliceCopy(t *testing.T) {
	sample := make([]byte, 100)
	if _, err := rand.Read(sample); err != nil {
		t.Fatal("Error generating random bytes:", err)
	}
	result := ShuffleSliceCopy(sample)
	require.ElementsMatch(t, sample, result)
	require.NotEqualValues(t, sample, result)
}

func Test_TransformSlice(t *testing.T) {
	type foo struct {
		name  string
		value int
	}
	pairs := []foo{{"a", 1}, {"c", 3}, {"b", 2}}
	names := TransformSlice(pairs, func(v foo) string { return v.name })
	require.Equal(t, []string{"a", "c", "b"}, names)
}
