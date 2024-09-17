package interface_uc_array_cbor_tags

import (
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
)

type (
	UnicityCertificateV2 struct {
		_      struct{} `cbor:",toarray"`
		FieldB int
	}
)

func (uc *UnicityCertificateV2) Validate() error {
	return nil
}

func (uc *UnicityCertificateV2) GetVersion() ABTag {
	return UC2Tag
}

func (uc *UnicityCertificateV2) MarshalCBOR() ([]byte, error) {
	type alias UnicityCertificateV2
	return types.Cbor.Marshal(cbor.Tag{
		Number:  uint64(UC2Tag),
		Content: (*alias)(uc),
	})
}

func (uc *UnicityCertificateV2) UnmarshallCBOR(data []byte) error {
	return types.Cbor.Unmarshal(data, uc)
}
