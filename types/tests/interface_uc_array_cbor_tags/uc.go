package interface_uc_named_cbor

type (
	UnicityCertificate interface {
		Validate() error
		GetVersion() ABTag
	}

	UnicityCertificateV1 struct {
		_      struct{} `cbor:",toarray"`
		FieldA string
	}

	UnicityCertificateV2 struct {
		_      struct{} `cbor:",toarray"`
		FieldB int
	}
)

func (uc UnicityCertificateV1) Validate() error {
	return nil
}

func (uc UnicityCertificateV2) Validate() error {
	return nil
}

func (uc UnicityCertificateV1) GetVersion() ABTag {
	return UC1Tag
}

func (uc UnicityCertificateV2) GetVersion() ABTag {
	return UC2Tag
}
