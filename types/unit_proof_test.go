package types

import (
	"crypto"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

type alwaysValid struct{}
type alwaysInvalid struct{}

func (a *alwaysValid) Validate(*UnicityCertificate, []byte) error {
	return nil
}

func (a alwaysInvalid) Validate(*UnicityCertificate, []byte) error {
	return errors.New("invalid uc")
}

func TestVerifyUnitStateProof(t *testing.T) {
	emptyUC, err := (&UnicityCertificate{}).MarshalCBOR()
	require.NoError(t, err)

	t.Run("unit state proof is nil", func(t *testing.T) {
		data := &UnitState{}
		var usp *UnitStateProof
		require.EqualError(t, usp.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "invalid unit state proof: unit state proof is nil")
	})

	t.Run("unit ID missing", func(t *testing.T) {
		data := &UnitState{}
		usp := &UnitStateProof{}
		require.EqualError(t, usp.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "invalid unit state proof: unit ID is unassigned")
	})

	t.Run("unit tree cert missing", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID: []byte{0},
		}
		data := &UnitState{}
		require.EqualError(t, proof.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "invalid unit state proof: unit tree cert is nil")
	})

	t.Run("state tree cert missing", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:       []byte{0},
			UnitTreeCert: &UnitTreeCert{},
		}
		data := &UnitState{}
		require.EqualError(t, proof.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "invalid unit state proof: state tree cert is nil")
	})

	t.Run("unicity certificate missing", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:        []byte{0},
			UnitTreeCert:  &UnitTreeCert{},
			StateTreeCert: &StateTreeCert{},
		}
		data := &UnitState{}
		require.EqualError(t, proof.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "invalid unit state proof: unicity certificate is nil")
	})

	t.Run("invalid unicity certificate", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &UnitState{}
		require.EqualError(t, proof.Verify(crypto.SHA256, data, &alwaysInvalid{}, nil), "invalid unicity certificate: invalid uc")
	})

	t.Run("missing unit data", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		require.EqualError(t, proof.Verify(crypto.SHA256, nil, &alwaysValid{}, nil), "unit state is nil")
	})

	t.Run("unit data hash invalid", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &UnitState{}
		require.EqualError(t, proof.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "unit state hash does not match unit state hash in unit tree cert")
	})

	t.Run("invalid summary value", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &UnitState{}
		proof.UnitTreeCert.UnitStateHash = doHash(t, data)
		uc, err := proof.getUCv1()
		require.NoError(t, err)
		uc.InputRecord = &InputRecord{SummaryValue: []byte{1}}
		proof.UnicityCertificate, err = uc.MarshalCBOR()
		require.NoError(t, err)
		require.EqualError(t, proof.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "invalid summary value: expected 01, got 0000000000000000")
	})

	t.Run("invalid state root hash", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &UnitState{}
		proof.UnitTreeCert.UnitStateHash = doHash(t, data)
		uc, err := proof.getUCv1()
		require.NoError(t, err)
		uc.InputRecord = &InputRecord{SummaryValue: []byte{0, 0, 0, 0, 0, 0, 0, 0}}
		proof.UnicityCertificate, err = uc.MarshalCBOR()
		require.NoError(t, err)
		require.ErrorContains(t, proof.Verify(crypto.SHA256, data, &alwaysValid{}, nil), "invalid state root hash")
	})

	t.Run("verify - ok", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		unitState := &UnitState{}
		proof.UnitTreeCert.UnitStateHash = doHash(t, unitState)

		uc, err := proof.getUCv1()
		require.NoError(t, err)
		uc.InputRecord = &InputRecord{SummaryValue: []byte{0, 0, 0, 0, 0, 0, 0, 0}}
		hash, _ := hexutil.Decode("0x17F0AC4A7E99A8C5B84FA792DF6D3657E66A4CA5EBE8010D67BDE8DF47516602")
		uc.InputRecord.Hash = hash
		proof.UnicityCertificate, err = uc.MarshalCBOR()
		require.NoError(t, err)
		require.NoError(t, proof.Verify(crypto.SHA256, unitState, &alwaysValid{}, nil), "unexpected error")
	})
}

func Test_UnitStateProof_CBOR(t *testing.T) {
	emptyUC, err := (&UnicityCertificate{}).MarshalCBOR()
	require.NoError(t, err)

	t.Run("marshal CBOR - ok", func(t *testing.T) {
		proof := &UnitStateProof{
			Version:            1,
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		proofBytes, err := proof.MarshalCBOR()
		require.NoError(t, err)

		proof2 := &UnitStateProof{}
		require.NoError(t, proof2.UnmarshalCBOR(proofBytes))
		require.Equal(t, proof, proof2)
	})

	t.Run("marshal CBOR - invalid version", func(t *testing.T) {
		proof := &UnitStateProof{
			Version:            2,
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		proofBytes, err := proof.MarshalCBOR()
		require.NoError(t, err)

		proof2 := &UnitStateProof{}
		require.ErrorContains(t, proof2.UnmarshalCBOR(proofBytes), "invalid version (type *types.UnitStateProof), expected 1, got 2")
	})
}
