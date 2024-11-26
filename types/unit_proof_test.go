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

func (a *alwaysValid) Validate(*UnicityCertificate) error {
	return nil
}

func (a alwaysInvalid) Validate(*UnicityCertificate) error {
	return errors.New("invalid uc")
}

func TestVerifyUnitStateProof(t *testing.T) {
	emptyUC, err := (&UnicityCertificate{}).MarshalCBOR()
	require.NoError(t, err)

	t.Run("unit state proof is nil", func(t *testing.T) {
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(nil, crypto.SHA256, data, &alwaysValid{}), "unit state proof is nil")
	})
	t.Run("unit ID missing", func(t *testing.T) {
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(&UnitStateProof{}, crypto.SHA256, data, &alwaysValid{}), "unit ID is nil")
	})
	t.Run("unit tree cert missing", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID: []byte{0},
		}
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "unit tree cert is nil")
	})
	t.Run("state tree cert missing", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:       []byte{0},
			UnitTreeCert: &UnitTreeCert{},
		}
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "state tree cert is nil")
	})
	t.Run("unicity certificate missing", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:        []byte{0},
			UnitTreeCert:  &UnitTreeCert{},
			StateTreeCert: &StateTreeCert{},
		}
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "unicity certificate is nil")
	})
	t.Run("invalid unicity certificate", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysInvalid{}), "invalid unicity certificate")
	})
	t.Run("missing unit data", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, nil, &alwaysValid{}), "unit data is nil")
	})
	t.Run("unit data hash invalid", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "unit data hash does not match hash in unit tree")
	})
	t.Run("invalid summary value", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &StateUnitData{}
		proof.UnitTreeCert.UnitDataHash = doHash(t, data)
		uc, err := proof.getUCv1()
		require.NoError(t, err)
		uc.InputRecord = &InputRecord{SummaryValue: []byte{1}}
		proof.UnicityCertificate, err = uc.MarshalCBOR()
		require.NoError(t, err)
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "invalid summary value")
	})
	t.Run("invalid state root hash", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &StateUnitData{}
		proof.UnitTreeCert.UnitDataHash = doHash(t, data)
		uc, err := proof.getUCv1()
		require.NoError(t, err)
		uc.InputRecord = &InputRecord{SummaryValue: []byte{0, 0, 0, 0, 0, 0, 0, 0}}
		proof.UnicityCertificate, err = uc.MarshalCBOR()
		require.NoError(t, err)
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "invalid state root hash")
	})
	t.Run("verify - ok", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: emptyUC,
		}
		data := &StateUnitData{}
		proof.UnitTreeCert.UnitDataHash = doHash(t, data)

		uc, err := proof.getUCv1()
		require.NoError(t, err)
		uc.InputRecord = &InputRecord{SummaryValue: []byte{0, 0, 0, 0, 0, 0, 0, 0}}
		hash, _ := hexutil.Decode("0x74F08E087DBBC89F0ED682530AB430B9FE50D96B45E54185F44B386BF11716C1")
		uc.InputRecord.Hash = hash
		proof.UnicityCertificate, err = uc.MarshalCBOR()
		require.NoError(t, err)
		require.NoError(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "unexpected error")
	})
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
