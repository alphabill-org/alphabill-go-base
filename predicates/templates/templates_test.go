package templates

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alphabill-org/alphabill-go-base/cbor"
	"github.com/alphabill-org/alphabill-go-base/predicates"
)

func Test_templateBytes(t *testing.T) {
	t.Parallel()

	/*
		Make sure that CBOR encoder hasn't changed how it encodes our "hardcoded templates"
		or that the constants haven't been changed.
		If these tests fail it's a breaking change!
	*/

	t.Run("always false", func(t *testing.T) {
		buf, err := cbor.Marshal(predicates.Predicate{Tag: TemplateStartByte, Code: []byte{AlwaysFalseID}})
		require.NoError(t, err)
		require.True(t, bytes.Equal(buf, alwaysFalseBytes), `CBOR representation of "always false" predicate template has changed (expected %X, got %X)`, alwaysFalseBytes, buf)
		require.True(t, bytes.Equal(alwaysFalseBytes, AlwaysFalseBytes()))
		pred := &predicates.Predicate{}
		require.NoError(t, cbor.Unmarshal(buf, pred))
		require.Equal(t, pred.Code[0], AlwaysFalseID, "always false predicate ID")
	})

	t.Run("always true", func(t *testing.T) {
		buf, err := cbor.Marshal(predicates.Predicate{Tag: TemplateStartByte, Code: []byte{AlwaysTrueID}})
		require.NoError(t, err)
		require.True(t, bytes.Equal(buf, alwaysTrueBytes), `CBOR representation of "always true" predicate template has changed (expected %X, got %X)`, alwaysTrueBytes, buf)
		require.True(t, bytes.Equal(alwaysTrueBytes, AlwaysTrueBytes()))
		pred := &predicates.Predicate{}
		require.NoError(t, cbor.Unmarshal(buf, pred))
		require.Equal(t, pred.Code[0], AlwaysTrueID, "always true predicate ID")
	})

	t.Run("p2pkh", func(t *testing.T) {
		pubKeyHash, err := hex.DecodeString("F52022BB450407D92F13BF1C53128A676BCF304818E9F41A5EF4EBEAE9C0D6B0")
		require.NoError(t, err)
		buf, err := cbor.Marshal(predicates.Predicate{Tag: TemplateStartByte, Code: []byte{P2pkh256ID}, Params: pubKeyHash})
		require.NoError(t, err)

		fromHex, err := hex.DecodeString("830041025820F52022BB450407D92F13BF1C53128A676BCF304818E9F41A5EF4EBEAE9C0D6B0")
		require.NoError(t, err)

		require.Equal(t, buf, fromHex)
	})
}

func Test_ExtractPubKeyHashFromP2pkhPredicate(t *testing.T) {
	pubKeyHash, err := hex.DecodeString("F52022BB450407D92F13BF1C53128A676BCF304818E9F41A5EF4EBEAE9C0D6B0")
	require.NoError(t, err)

	result, err := ExtractPubKeyHashFromP2pkhPredicate(NewP2pkh256BytesFromKeyHash(pubKeyHash))
	require.NoError(t, err)
	require.Equal(t, pubKeyHash, result)
}

func Test_IsP2pkhTemplate(t *testing.T) {
	t.Parallel()

	t.Run("p2pkh template true", func(t *testing.T) {
		require.NoError(t, VerifyP2pkhPredicate(&predicates.Predicate{Tag: TemplateStartByte, Code: []byte{P2pkh256ID}}))
	})

	t.Run("p2pkh template false", func(t *testing.T) {
		require.Error(t, VerifyP2pkhPredicate(nil))
		require.Error(t, VerifyP2pkhPredicate(&predicates.Predicate{}))
		require.Error(t, VerifyP2pkhPredicate(&predicates.Predicate{Tag: 999, Code: []byte{P2pkh256ID}}))
		require.Error(t, VerifyP2pkhPredicate(&predicates.Predicate{Tag: TemplateStartByte, Code: []byte{P2pkh256ID, P2pkh256ID}}))
	})
}
