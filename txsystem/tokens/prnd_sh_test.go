package tokens

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alphabill-org/alphabill-go-base/types"
)

func Test_PrndSh(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		// asking for more bytes than supported
		buf := make([]byte, 300)
		f := PrndSh(&types.TransactionOrder{})
		require.EqualError(t, f(buf), `requested 300 bytes but got 32`)

		// not providing txo
		f = PrndSh(nil)
		require.EqualError(t, f(buf), `transaction order is nil`)
	})

	t.Run("success", func(t *testing.T) {
		txo := &types.TransactionOrder{}
		f := PrndSh(txo)

		buf := make([]byte, 32)
		require.NoError(t, f(buf))
		require.Len(t, buf, 32, "buffer length mustn't change")

		// calling again returns the same value
		buf2 := make([]byte, 32)
		require.NoError(t, f(buf2))
		require.Equal(t, buf, buf2)

		// smaller buffer, should be prefix of the longer one
		buf2 = make([]byte, 10)
		require.NoError(t, f(buf2))
		require.True(t, bytes.HasPrefix(buf, buf2))
		require.Len(t, buf2, 10, "buffer length mustn't change")

		// changing attributes or metadata generates different value
		txo.ClientMetadata = &types.ClientMetadata{Timeout: 100}
		f = PrndSh(txo)
		buf2 = make([]byte, 32)
		require.NoError(t, f(buf2))
		require.NotEqual(t, buf, buf2)
	})
}
