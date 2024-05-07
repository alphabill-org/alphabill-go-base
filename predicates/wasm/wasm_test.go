package wasm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_PredicateParams_IsValid(t *testing.T) {
	t.Run("missing entrypoint", func(t *testing.T) {
		pp := PredicateParams{}
		require.EqualError(t, pp.IsValid(), `predicate function name (entrypoint) must be assigned`)
	})

	t.Run("success", func(t *testing.T) {
		pp := PredicateParams{Entrypoint: "F"}
		require.NoError(t, pp.IsValid())

		p2 := &PredicateParams{Entrypoint: "fn_name", Args: []byte{}}
		require.NoError(t, p2.IsValid())
	})
}
