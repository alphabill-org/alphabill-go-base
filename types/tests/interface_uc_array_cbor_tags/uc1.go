package interface_uc_array_cbor_tags

import (
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
)

type (
	UnicityCertificateV1 struct {
		_      struct{} `cbor:",toarray"`
		FieldA string
	}
)

func (uc *UnicityCertificateV1) Validate() error {
	return nil
}

func (uc *UnicityCertificateV1) GetVersion() ABTag {
	return UC1Tag
}

func (uc *UnicityCertificateV1) MarshalCBOR() ([]byte, error) {
	type alias UnicityCertificateV1
	return types.Cbor.Marshal(cbor.Tag{
		Number:  uint64(UC1Tag),
		Content: (*alias)(uc),
	})
}

func (uc *UnicityCertificateV1) UnmarshalCBOR(data []byte) error {
	type alias UnicityCertificateV1
	var aux = (*alias)(uc)
	return types.Cbor.Unmarshal(data, aux)
}
