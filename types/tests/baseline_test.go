package tests

/*
 * This just shows that if we stick to the fields of 'struct' type of UC,
 * we need to copy the Block each time we change UC
 */
type (
	Block1 struct {
		_      struct{} `cbor:",toarray"`
		Header *Header1
		UC     *UnicityCertificate1
	}

	Header1 struct {
		_        struct{} `cbor:",toarray"`
		SystemID uint32
	}

	UnicityCertificate1 struct {
		_           struct{} `cbor:",toarray"`
		InputRecord string
	}

	Block2 struct {
		_      struct{} `cbor:",toarray"`
		Header *Header2
		UC     *UnicityCertificate2
	}

	Header2 struct {
		_        struct{} `cbor:",toarray"`
		SystemID uint32
	}

	UnicityCertificate2 struct {
		_           struct{} `cbor:",toarray"`
		InputRecord string
	}
)
