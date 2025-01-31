package types

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	test "github.com/alphabill-org/alphabill-go-base/testutils"
	testsig "github.com/alphabill-org/alphabill-go-base/testutils/sig"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

func TestUnicitySeal_IsValid(t *testing.T) {
	randomHash := test.RandomBytes(32)

	validUS := func() UnicitySeal {
		return UnicitySeal{
			Version:              1,
			NetworkID:            2,
			RootChainRoundNumber: 3,
			Epoch:                4,
			Timestamp:            NewTimestamp(),
			PreviousHash:         randomHash,
			Hash:                 randomHash,
			// IsValid doesn't actually verify the signature(s) so we just need
			// some non empty value, doesn't actually have to be valid signature
			Signatures: map[string]hex.Bytes{"test": randomHash},
		}
	}
	us := validUS()
	require.NoError(t, us.IsValid(), "validUC helper returns invalid UC")

	t.Run("seal is nil", func(t *testing.T) {
		var seal *UnicitySeal = nil
		require.Error(t, seal.IsValid(), ErrUnicitySealIsNil)
	})

	t.Run("hash is nil", func(t *testing.T) {
		seal := validUS()
		seal.Hash = nil
		require.ErrorIs(t, seal.IsValid(), ErrUnicitySealHashIsNil)
	})

	t.Run("root round is invalid", func(t *testing.T) {
		seal := validUS()
		seal.RootChainRoundNumber = 0
		require.ErrorIs(t, seal.IsValid(), ErrInvalidRootRound)
	})

	t.Run("timestamp is missing", func(t *testing.T) {
		seal := validUS()
		seal.Timestamp = 0
		require.ErrorIs(t, seal.IsValid(), ErrInvalidTimestamp)

		seal.Timestamp = GenesisTime - 1
		require.ErrorIs(t, seal.IsValid(), ErrInvalidTimestamp)
	})

	t.Run("signatures", func(t *testing.T) {
		seal := validUS()
		seal.Signatures = nil
		require.ErrorIs(t, seal.IsValid(), ErrUnicitySealSignatureIsNil)

		seal.Signatures = SignatureMap{}
		require.ErrorIs(t, seal.IsValid(), ErrUnicitySealSignatureIsNil)

		seal.Signatures = SignatureMap{"": []byte{1}}
		require.EqualError(t, seal.IsValid(), `signature without signer ID`)

		seal.Signatures = SignatureMap{"signer": nil}
		require.EqualError(t, seal.IsValid(), `empty signature for "signer"`)

		seal.Signatures = SignatureMap{"signer": []byte{}}
		require.EqualError(t, seal.IsValid(), `empty signature for "signer"`)
	})
}

func TestUnicitySeal_Verify(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	trustBase := NewTrustBase(t, verifier)
	randomHash := test.RandomBytes(32)

	// createUS returns UnicitySeal which is not signed but otherwise valid(ish)
	createUS := func() UnicitySeal {
		return UnicitySeal{
			Version:              1,
			NetworkID:            2,
			RootChainRoundNumber: 3,
			Epoch:                4,
			Timestamp:            NewTimestamp(),
			PreviousHash:         randomHash,
			Hash:                 randomHash,
		}
	}

	t.Run("IsValid is called", func(t *testing.T) {
		// Verify should call IsValid before any other checks and is
		// the receiver not nil is first check there
		var seal *UnicitySeal = nil
		require.Error(t, seal.Verify(trustBase), ErrUnicitySealIsNil)
	})

	t.Run("no trust base", func(t *testing.T) {
		seal := createUS()
		require.Error(t, seal.Verify(nil), ErrRootValidatorInfoMissing)
	})

	t.Run("invalid signature", func(t *testing.T) {
		// signer "test" is in the trust base but we assign invalid signature
		seal := createUS()
		seal.Signatures = map[string]hex.Bytes{"test": randomHash}
		// should fail with "invalid signature"? AB-1861
		err := seal.Verify(trustBase)
		require.EqualError(t, err, "verifying signatures: quorum not reached, signed_votes=0 quorum_threshold=1")
	})

	t.Run("unknown signer", func(t *testing.T) {
		// signer "foobar" is not in the trustBase
		signerFoo, _ := testsig.CreateSignerAndVerifier(t)
		seal := createUS()
		require.NoError(t, seal.Sign("foobar", signerFoo))
		// should fail with "unknown signer"? AB-1861
		err := seal.Verify(trustBase)
		require.EqualError(t, err, "verifying signatures: quorum not reached, signed_votes=0 quorum_threshold=1")
	})

	t.Run("no quorum", func(t *testing.T) {
		// trust base has two nodes but seal has only one signature - not a quorum
		seal := createUS()
		require.NoError(t, seal.Sign("test", signer))
		_, verifier2 := testsig.CreateSignerAndVerifier(t)
		tb := NewTrustBaseFromVerifiers(t, map[string]abcrypto.Verifier{"test": verifier, "2": verifier2})
		err := seal.Verify(tb)
		require.EqualError(t, err, "verifying signatures: quorum not reached, signed_votes=1 quorum_threshold=2")
	})

	t.Run("OK", func(t *testing.T) {
		seal := createUS()
		require.NoError(t, seal.Sign("test", signer))
		require.NoError(t, seal.Verify(trustBase))
	})
}

func TestSign_SignerIsNil(t *testing.T) {
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         []byte{1, 1, 1},
		Hash:                 []byte{2, 2, 2},
	}
	err := seal.Sign("test", nil)
	require.ErrorIs(t, err, ErrSignerIsNil)
}

func Test_NewTimestamp(t *testing.T) {
	require.NotZero(t, NewTimestamp())
}

func TestSeal_AddToHasher(t *testing.T) {
	randomHash := test.RandomBytes(32)
	seal := &UnicitySeal{
		RootChainRoundNumber: 1,
		Timestamp:            NewTimestamp(),
		PreviousHash:         randomHash,
		Hash:                 randomHash,
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
		Hash:                 test.RandomBytes(32),
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
		Hash:                 []byte{4, 4, 5, 4},
		NewField:             "test",
	}

	data, err := Cbor.MarshalTagged(UnicitySealTag, seal2.version, seal2.RootChainRoundNumber, seal2.Timestamp, seal2.PreviousHash, seal2.Hash, seal2.Signatures, seal2.NewField)
	require.NoError(t, err)

	// decode into version 1
	res := &UnicitySeal{}
	require.Error(t, Cbor.Unmarshal(data, res))
}

func TestUnicitySeal_UnmarshalCBOR(t *testing.T) {
	t.Run("Valid Version 1", func(t *testing.T) {
		sigs := SignatureMap{"node id": []byte{5, 1, 9}}
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, []byte{6}, []byte{7}, sigs)
		require.NoError(t, err)
		seal := UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.NoError(t, err)
		require.Equal(t, ABVersion(1), seal.GetVersion())
		require.Equal(t, NetworkID(2), seal.NetworkID)
		require.Equal(t, uint64(3), seal.RootChainRoundNumber)
		require.Equal(t, uint64(4), seal.Epoch)
		require.Equal(t, uint64(5), seal.Timestamp)
		require.Equal(t, hex.Bytes{6}, seal.PreviousHash)
		require.Equal(t, hex.Bytes{7}, seal.Hash)
		require.Equal(t, sigs, seal.Signatures)
	})

	t.Run("InvalidTag", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(1000, ABVersion(1), uint64(1), uint64(1), []byte{0xFF}, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, "unmarshaling UnicitySeal: expected tag 1001, got 1000")
	})

	t.Run("Invalid encoding", func(t *testing.T) {
		// testing that the number of fields is correct according to the version
		// currently only version 1 is in use, must have 8 fields
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, []byte{4}, []byte{5})
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, "unsupported UnicitySeal encoding, version 1 with 5 fields")

		// correct number of fields for version 1 but version is set to be 2
		data, err = Cbor.MarshalTagged(UnicitySealTag, ABVersion(2), 2, 3, 4, 5, []byte{6}, []byte{7}, nil)
		require.NoError(t, err)
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, "unsupported UnicitySeal encoding, version 2 with 8 fields")
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, "42", uint64(1), uint64(1), []byte{0xFF}, []byte{0xFF}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `unmarshaling UnicitySeal: expected version number to be uint64, got: "42"`)
	})

	t.Run("NetworkID", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 1.2, 3, 4, 5, []byte{6}, []byte{7}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid network ID, expected uint64 got float64`)
	})

	t.Run("InvalidRootRoundNumber", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, "3", 4, 5, []byte{6}, []byte{7}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid root round number, expected uint64 got string`)
	})

	t.Run("Epoch", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, []byte{4}, 5, []byte{6}, []byte{7}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid epoch, expected uint64 got []uint8`)
	})

	t.Run("InvalidTimestamp", func(t *testing.T) {
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, nil, []byte{6}, []byte{7}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid timestamp, expected uint64 got <nil>`)
	})

	t.Run("PreviousHash", func(t *testing.T) {
		// nil is valid
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, nil, []byte{7}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		require.NoError(t, seal.UnmarshalCBOR(data))
		require.Nil(t, seal.PreviousHash)

		// PreviousHash is []byte, use string instead
		data, err = Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, "6", []byte{7}, nil)
		require.NoError(t, err)
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid previous hash, expected byte slice got string`)
	})

	t.Run("Hash", func(t *testing.T) {
		// nil is valid
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, []byte{6}, nil, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		require.NoError(t, seal.UnmarshalCBOR(data))
		require.Nil(t, seal.Hash)

		// Hash is []byte, use int instead
		data, err = Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, []byte{6}, 7, nil)
		require.NoError(t, err)
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid hash, expected byte slice got uint64`)
	})

	t.Run("Signatures", func(t *testing.T) {
		// nil is accepted
		data, err := Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, []byte{6}, []byte{7}, nil)
		require.NoError(t, err)
		seal := &UnicitySeal{}
		require.NoError(t, seal.UnmarshalCBOR(data))
		require.Nil(t, seal.Signatures)

		// invalid type, slice instead of map
		data, err = Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, []byte{6}, []byte{7}, []byte{8})
		require.NoError(t, err)
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `unicity seal: invalid signatures, expected map, got []uint8`)

		// invalid key type
		signatures := map[any]any{1: []byte{1, 2, 3}}
		data, err = Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, []byte{6}, []byte{7}, signatures)
		require.NoError(t, err)
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid signer ID type: uint64`)

		// invalid value type
		signatures = map[any]any{"1": "signature"}
		data, err = Cbor.MarshalTagged(UnicitySealTag, ABVersion(1), 2, 3, 4, 5, []byte{6}, []byte{7}, signatures)
		require.NoError(t, err)
		err = seal.UnmarshalCBOR(data)
		require.EqualError(t, err, `invalid signature type: string`)
	})
}
