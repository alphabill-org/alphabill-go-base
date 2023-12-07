package types

import (
	"crypto"
	"errors"
	"testing"

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
			UnicityCertificate: &UnicityCertificate{},
		}
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysInvalid{}), "invalid unicity certificate")
	})
	t.Run("missing unit data", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: &UnicityCertificate{},
		}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, nil, &alwaysValid{}), "unit data is nil")
	})
	t.Run("unit data hash invalid", func(t *testing.T) {
		proof := &UnitStateProof{
			UnitID:             []byte{0},
			UnitTreeCert:       &UnitTreeCert{},
			StateTreeCert:      &StateTreeCert{},
			UnicityCertificate: &UnicityCertificate{},
		}
		data := &StateUnitData{}
		require.ErrorContains(t, VerifyUnitStateProof(proof, crypto.SHA256, data, &alwaysValid{}), "unit data hash does not match hash in unit tree")
	})
}
