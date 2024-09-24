package cbor_inline

import (
	"testing"

	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/stretchr/testify/require"
)

/*
In this version Block holds UC in CBOR encoded form
*/
type (
	Block struct {
		_      struct{} `cbor:",toarray"`
		Header *Header
		UC     types.RawCBORSequence // <version;UC>
	}

	Header struct {
		_        struct{} `cbor:",toarray"`
		SystemID uint32
	}

	UnicityCertificate1 struct {
		_           struct{} `cbor:",toarray"`
		InputRecord string
	}

	UnicityCertificate2 struct {
		_            struct{} `cbor:",toarray"`
		InputRecord  string
		AnotherField int
	}
)

func TestBlock_uc1(t *testing.T) {
	uc1 := &UnicityCertificate1{
		InputRecord: "input record 1",
	}

	uc1bytes, err := types.Cbor.MarshalVersioned(getUCVersion(uc1), uc1)
	require.NoError(t, err)
	block1 := &Block{
		Header: &Header{
			SystemID: 1,
		},
		UC: uc1bytes,
	}
	block1bytes, err := types.Cbor.Marshal(block1)
	require.NoError(t, err)

	var block1decoded Block
	err = types.Cbor.Unmarshal(block1bytes, &block1decoded)
	require.NoError(t, err)

	require.Equal(t, *block1, block1decoded)

	decodeAndCheckUC(t, block1decoded, uc1)
}

func TestBlock_uc2(t *testing.T) {
	uc := &UnicityCertificate2{
		InputRecord:  "input record 2",
		AnotherField: 42,
	}

	ucBytes, err := types.Cbor.MarshalVersioned(getUCVersion(uc), uc)
	require.NoError(t, err)
	block1 := &Block{
		Header: &Header{
			SystemID: 1,
		},
		UC: ucBytes,
	}
	block1bytes, err := types.Cbor.Marshal(block1)
	require.NoError(t, err)

	var block1decoded Block
	err = types.Cbor.Unmarshal(block1bytes, &block1decoded)
	require.NoError(t, err)

	require.Equal(t, *block1, block1decoded)

	decodeAndCheckUC(t, block1decoded, uc)
}

func decodeAndCheckUC(t *testing.T, bl Block, expectedUC any) {
	version, rest, err := types.Cbor.UnmarshalVersion(bl.UC)
	require.NoError(t, err)

	switch version {
	case 1:
		var uc1decoded UnicityCertificate1
		err = types.Cbor.Unmarshal(rest, &uc1decoded)
		require.NoError(t, err)
		require.Equal(t, expectedUC, &uc1decoded)
	case 2:
		var uc2decoded UnicityCertificate2
		err = types.Cbor.Unmarshal(rest, &uc2decoded)
		require.NoError(t, err)
		require.Equal(t, expectedUC, &uc2decoded)
	default:
		require.Fail(t, "unexpected version")
	}
}

func getUCVersion(uc any) types.Version {
	switch uc.(type) {
	case *UnicityCertificate1:
		return 1
	case *UnicityCertificate2:
		return 2
	default:
		return 0
	}
}
