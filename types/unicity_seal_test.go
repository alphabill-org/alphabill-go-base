package types

import (
	"crypto"
	"testing"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/stretchr/testify/require"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	test "github.com/alphabill-org/alphabill-go-base/testutils"
	testsig "github.com/alphabill-org/alphabill-go-base/testutils/sig"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

var zeroHash = make([]byte, 32)

func TestUnicitySeal_IsValid(t *testing.T) {
	_, verifier := testsig.CreateSignerAndVerifier(t)
	t.Run("seal is nil", func(t *testing.T) {
		var seal *UnicitySeal = nil
		tb := NewTrustBase(t, verifier)
		require.Error(t, seal.Verify(tb), ErrUnicitySealIsNil)
	})
	t.Run("no root nodes", func(t *testing.T) {
		seal := UnicitySeal{}
		require.Error(t, seal.Verify(nil), ErrRootValidatorInfoMissing)
	})
	t.Run("hash is nil", func(t *testing.T) {
		seal := &UnicitySeal{
			RootChainRoundNumber: 1,
			Timestamp:            NewTimestamp(),
			PreviousHash:         zeroHash,
			Hash:                 nil,
			Signatures:           map[string]hex.Bytes{"": zeroHash},
		}
		tb := NewTrustBase(t, verifier)
		require.Error(t, seal.Verify(tb), ErrUnicitySealHashIsNil)
	})
	t.Run("root round is invalid", func(t *testing.T) {
		seal := &UnicitySeal{
			RootChainRoundNumber: 0,
			Timestamp:            NewTimestamp(),
			PreviousHash:         zeroHash,
			Hash:                 zeroHash,
			Signatures:           nil,
		}
		tb := NewTrustBase(t, verifier)
		require.Error(t, seal.Verify(tb), ErrInvalidRootRound)
	})
	t.Run("timestamp is missing", func(t *testing.T) {
		seal := &UnicitySeal{
			RootChainRoundNumber: 1,
			PreviousHash:         zeroHash,
			Hash:                 zeroHash,
			Signatures:           nil,
		}
		tb := NewTrustBase(t, verifier)
		require.Error(t, seal.Verify(tb), ErrInvalidTimestamp)
	})
}

func TestIsValid_InvalidSignature(t *testing.T) {
	_, verifier := testsig.CreateSignerAndVerifier(t)
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
		Signatures:           map[string]hex.Bytes{"test": zeroHash},
	}
	tb := NewTrustBase(t, verifier)

	err := seal.Verify(tb)
	require.ErrorContains(t, err, "quorum not reached")
}

func TestSignAndVerify_Ok(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
	}
	err := seal.Sign("test", signer)
	require.NoError(t, err)
	tb := NewTrustBase(t, verifier)
	err = seal.Verify(tb)
	require.NoError(t, err)
}

func TestSignAndVerify_QuorumNotReached(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
	}
	err := seal.Sign("test", signer)
	require.NoError(t, err)
	_, verifier2 := testsig.CreateSignerAndVerifier(t)
	tb := NewTrustBaseFromVerifiers(t, map[string]abcrypto.Verifier{"test": verifier, "2": verifier2})
	err = seal.Verify(tb)
	require.ErrorContains(t, err, "quorum not reached")
}

func TestVerify_SignatureIsNil(t *testing.T) {
	_, verifier := testsig.CreateSignerAndVerifier(t)
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
	}
	tb := NewTrustBase(t, verifier)
	err := seal.Verify(tb)
	require.EqualError(t, err, "invalid unicity seal: no signatures")
}

func TestVerify_SignatureUnknownSigner(t *testing.T) {
	_, verifier := testsig.CreateSignerAndVerifier(t)
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
		Signatures:           map[string]hex.Bytes{"test": test.RandomBytes(64)},
	}
	tb := NewTrustBase(t, verifier)
	err := seal.Verify(tb)
	require.ErrorContains(t, err, "quorum not reached")
}

func TestSign_SignerIsNil(t *testing.T) {
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
	}
	err := seal.Sign("test", nil)
	require.ErrorIs(t, err, ErrSignerIsNil)
}

func TestVerify_VerifierIsNil(t *testing.T) {
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
		Signatures:           map[string]hex.Bytes{"": zeroHash},
	}
	err := seal.Verify(nil)
	require.ErrorIs(t, err, ErrRootValidatorInfoMissing)
}

func Test_NewTimestamp(t *testing.T) {
	require.NotZero(t, NewTimestamp())
}

func TestSeal_AddToHasher(t *testing.T) {
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         zeroHash,
		Hash:                 zeroHash,
		Signatures:           map[string]hex.Bytes{"xxx": {1, 1, 1}, "aaa": {2, 2, 2}},
	}
	hasher := abhash.New(crypto.SHA256.New())
	seal.AddToHasher(hasher)
	hash, err := hasher.Sum()
	require.NoError(t, err)

	// serialize manually
	hasher.Reset()
	sealBytes, err := seal.MarshalCBOR()
	require.NoError(t, err)
	hasher.WriteRaw(sealBytes)

	hash2, err := hasher.Sum()
	require.NoError(t, err)

	require.Equal(t, hash, hash2)
}

func TestUnicitySeal_cbor(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         nil,
		Hash:                 zeroHash,
	}

	err := seal.Sign("test", signer)
	require.NoError(t, err)

	tb := NewTrustBase(t, verifier)
	err = seal.Verify(tb)
	require.NoError(t, err)

	data, err := Cbor.Marshal(seal)
	require.NoError(t, err)

	res := &UnicitySeal{}
	require.NoError(t, Cbor.Unmarshal(data, res))
	require.Equal(t, seal.GetVersion(), res.GetVersion())
	// `seal.version` is not set, but serialized correctly
	// set it to correct value for comparison with 'res'
	seal.Version = seal.GetVersion()
	require.EqualValues(t, seal, res)

	err = res.Verify(tb)
	require.NoError(t, err)
}

func TestUnicitySeal_forwardCompatibility_notSupported(t *testing.T) {
	type TestUnicitySealV2 struct {
		_                    struct{} `cbor:",toarray"`
		version              ABVersion
		RootChainRoundNumber uint64
		Timestamp            uint64
		PreviousHash         []byte
		Hash                 []byte
		Signatures           SignatureMap
		NewField             string // added in version 2 (tag: 1002)
	}

	seal2 := &TestUnicitySealV2{
		version:              2,
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         nil,
		Hash:                 zeroHash,
		NewField:             "test",
	}

	data, err := Cbor.MarshalTagged(UnicitySealTag, seal2.version, seal2.RootChainRoundNumber, seal2.Timestamp, seal2.PreviousHash, seal2.Hash, seal2.Signatures, seal2.NewField)
	require.NoError(t, err)

	// decode into version 1
	res := &UnicitySeal{}
	require.Error(t, Cbor.Unmarshal(data, res))
}

func TestUnicitySeal_UnmarshalCBOR(t *testing.T) {
	t.Run("ValidData", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), uint64(1), uint64(1), []byte{0xFF}, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.NoError(t, err)
		require.Equal(t, ABVersion(1), seal.GetVersion())
		require.Equal(t, uint64(1), seal.RootChainRoundNumber)
		require.Equal(t, uint64(1), seal.Timestamp)
		require.Equal(t, hex.Bytes{0xFF}, seal.PreviousHash)
		require.Equal(t, hex.Bytes{0xFF}, seal.Hash)
		require.Nil(t, seal.Signatures)
	})

	t.Run("InvalidTag", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(1000, ABVersion(1), uint64(1), uint64(1), []byte{0xFF}, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "invalid tag 1000, expected 1001")
	})

	t.Run("InvalidArrayLength", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), uint64(1), uint64(1), []byte{0xFF}, []byte{0xFF})
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "invalid array length")
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, "42", uint64(1), uint64(1), []byte{0xFF}, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "unexpected type of version")
	})

	t.Run("InvalidRootRoundNumber", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), "1", uint64(1), []byte{0xFF}, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "unexpected type of root round number")
	})

	t.Run("InvalidTimestamp", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 1, []byte{}, []byte{0xFF}, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "unexpected type of timestamp")
	})

	t.Run("InvalidPreviousHash", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 1, 1, 0xFF, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "invalid previous hash")
	})

	t.Run("InvalidHash", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 1, 1, []byte{0xFF}, 0xFF, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "invalid hash")
	})

	t.Run("InvalidSignatures", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 1, 1, []byte{0xFF}, []byte{0xFF}, "")
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.ErrorContains(t, err, "invalid signatures")
	})
}
