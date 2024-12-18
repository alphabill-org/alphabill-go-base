package money

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alphabill-org/alphabill-go-base/types"
)

func Test_PrndSh(t *testing.T) {
	t.Run("not providing txo", func(t *testing.T) {
		require.Panics(t, func() { PrndSh(nil) })
	})

	t.Run("error", func(t *testing.T) {
		// asking for more bytes than supported
		buf := make([]byte, 300)
		f := PrndSh(&types.TransactionOrder{})
		require.EqualError(t, f(buf), `requested 300 bytes but got 32`)
	})

	t.Run("success", func(t *testing.T) {
		txo := &types.TransactionOrder{}
		f := PrndSh(txo)

		buf := make([]byte, 32)
		require.NoError(t, f(buf))
		require.Len(t, buf, 32, "buffer length mustn't change")

		// calling again returns different value
		buf2 := make([]byte, 32)
		require.NoError(t, f(buf2))
		require.NotEqual(t, buf, buf2, "each call must return different value")

		// resetting generator with original txo should return the first value again
		f = PrndSh(txo)
		require.NoError(t, f(buf2))
		require.Equal(t, buf, buf2)

		// use smaller buffer, should not be prefix of the longer one as each call
		// generates new byte sequence
		buf2 = make([]byte, 10)
		require.NoError(t, f(buf2))
		require.Len(t, buf2, 10, "buffer length mustn't change")
		require.False(t, bytes.HasPrefix(buf, buf2))
	})
}
