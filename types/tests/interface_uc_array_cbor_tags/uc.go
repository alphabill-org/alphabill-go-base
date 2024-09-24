package interface_uc_array_cbor_tags

import (
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/fxamacker/cbor/v2"
)

type UnicityCertificate interface {
	Versioned
	Validate() error
}

func decodeUnicityCertificate(data []byte) (UnicityCertificate, error) {
	var ucTag cbor.Tag
	if err := types.Cbor.Unmarshal(data, &ucTag); err != nil {
		return nil, err
	}

	var uc UnicityCertificate
	switch ABTag(ucTag.Number) {
	case UC1Tag:
		var uc1 UnicityCertificateV1
		if err := cbor.Unmarshal(data, &uc1); err != nil {
			return nil, err
		}
		uc = &uc1
	case UC2Tag:
		var uc2 UnicityCertificateV2
		if err := cbor.Unmarshal(data, &uc2); err != nil {
			return nil, err
		}
		uc = &uc2
	default:
		return nil, fmt.Errorf("unknown UnicityCertificate version: %d", ucTag.Number)
	}
	return uc, nil
}
