package mt

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestData struct {
	hash []byte
}

func (t *TestData) Hash(hash crypto.Hash) ([]byte, error) {
	return t.hash, nil
}

func TestNewMTWithNilData(t *testing.T) {
	var data []Data = nil
	mt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, mt)
	require.Nil(t, mt.GetRootHash())
	require.Equal(t, 0, mt.dataLength)
}

func TestNewMTWithEmptyData(t *testing.T) {
	mt, err := New(crypto.SHA256, []Data{})
	require.NoError(t, err)
	require.NotNil(t, mt)
	require.Nil(t, mt.GetRootHash())
	require.Equal(t, 0, mt.dataLength)
}

func TestNewMTWithSingleNode(t *testing.T) {
	data := []Data{&TestData{hash: make([]byte, 32)}}
	mt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, mt)
	require.NotNil(t, mt.GetRootHash())
	res, err := data[0].Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, res, mt.GetRootHash())
}

func TestNewMTWithOddNumberOfLeaves(t *testing.T) {
	var data = make([]Data, 7)
	for i := 0; i < len(data); i++ {
		data[i] = &TestData{hash: makeData(byte(i))}
	}
	mt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, mt)
	require.EqualValues(t, "7193803EC6A56B77DD2CDEC095724A0D60CBAE9D6D05174DF45941BF005739A9", fmt.Sprintf("%X", mt.GetRootHash()))
}

func TestNewMTWithEvenNumberOfLeaves(t *testing.T) {
	var data = make([]Data, 8)
	for i := 0; i < len(data); i++ {
		data[i] = &TestData{hash: makeData(byte(i))}
	}
	mt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, mt)
	require.EqualValues(t, "69C4FDAA2C74647D4EDFCB41B86975647B7C3AB80F73EC36A77614F982FE1C1B", fmt.Sprintf("%X", mt.GetRootHash()))
}

func TestSingleNodeTreeMerklePath(t *testing.T) {
	data := []Data{&TestData{hash: make([]byte, 32)}}
	mt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	path, err := mt.GetMerklePath(0)
	require.NoError(t, err)
	require.Nil(t, path)
}

func TestMerklePath(t *testing.T) {
	tests := []struct {
		name            string
		dataLength      int
		dataIdxToVerify int
		path            []*PathItem
		wantErr         error
	}{
		{
			name:            "verify leftmost node merkle path",
			dataLength:      8,
			dataIdxToVerify: 0,
			path: []*PathItem{
				{DirectionLeft: true, Hash: decodeHex("0100000000000000000000000000000000000000000000000000000000000000")},
				{DirectionLeft: true, Hash: decodeHex("BC8737A9C46FA1B8A60AD63E70D1376E193F8059D0888458AFB4198454876E07")},
				{DirectionLeft: true, Hash: decodeHex("A3B482CCC06795F7C9D87E40305899B2DAA334DF91A3A1FCD7C09A7354FD3EDD")},
			},
		},
		{
			name:            "verify rightmost node merkle path",
			dataLength:      8,
			dataIdxToVerify: 7,
			path: []*PathItem{
				{DirectionLeft: false, Hash: decodeHex("0600000000000000000000000000000000000000000000000000000000000000")},
				{DirectionLeft: false, Hash: decodeHex("F35E6B7B94801C39090A3621E798D4EB2E815955A719254FEFF472A814635B68")},
				{DirectionLeft: false, Hash: decodeHex("22707D03671D5EDF80EE90C32DA947BF2CA3CF3AA71A20C1C86A7F117DAD1B6B")},
			},
		},
		{
			name:            "verify middle node merkle path",
			dataLength:      8,
			dataIdxToVerify: 4,
			path: []*PathItem{
				{DirectionLeft: true, Hash: decodeHex("0500000000000000000000000000000000000000000000000000000000000000")},
				{DirectionLeft: true, Hash: decodeHex("540D0EB5979906647651AC1F57B42D51847F11F5FF7DBAD10A50E5170358F6E2")},
				{DirectionLeft: false, Hash: decodeHex("22707D03671D5EDF80EE90C32DA947BF2CA3CF3AA71A20C1C86A7F117DAD1B6B")},
			},
		},
		{
			name:            "verify two node merkle path",
			dataLength:      2,
			dataIdxToVerify: 0,
			path: []*PathItem{
				{DirectionLeft: true, Hash: decodeHex("0100000000000000000000000000000000000000000000000000000000000000")},
			},
		},
		{
			name:            "verify data index out of lower bound",
			dataLength:      8,
			dataIdxToVerify: -1,
			wantErr:         ErrIndexOutOfBounds,
		},
		{
			name:            "verify data index out of upper bound",
			dataLength:      8,
			dataIdxToVerify: 8,
			wantErr:         ErrIndexOutOfBounds,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data = make([]Data, tt.dataLength)
			for i := 0; i < len(data); i++ {
				data[i] = &TestData{hash: makeData(byte(i))}
			}
			mt, err := New(crypto.SHA256, data)
			require.NoError(t, err)
			merklePath, err := mt.GetMerklePath(tt.dataIdxToVerify)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, merklePath)
				require.Equal(t, len(tt.path), len(merklePath))
				for i := 0; i < len(tt.path); i++ {
					require.EqualValues(t, tt.path[i].DirectionLeft, merklePath[i].DirectionLeft)
					fmt.Printf("Actual: %X\n", merklePath[i].Hash)
					require.EqualValues(t, tt.path[i].Hash, merklePath[i].Hash)
				}
			}
		})
	}
}

func TestMerklePathEval(t *testing.T) {
	tests := []struct {
		name            string
		dataLength      int
		dataIdxToVerify int
	}{
		{
			name:            "verify leftmost node",
			dataLength:      8,
			dataIdxToVerify: 0,
		},
		{
			name:            "verify rightmost node",
			dataLength:      8,
			dataIdxToVerify: 7,
		},
		{
			name:            "verify middle node",
			dataLength:      8,
			dataIdxToVerify: 4,
		},
		{
			name:            "verify leftmost node (odd tree height)",
			dataLength:      4,
			dataIdxToVerify: 0,
		},
		{
			name:            "verify rightmost node (odd tree height)",
			dataLength:      4,
			dataIdxToVerify: 3,
		},
		{
			name:            "verify single node tree",
			dataLength:      1,
			dataIdxToVerify: 0,
		},
		{
			name:            "verify two node tree",
			dataLength:      2,
			dataIdxToVerify: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data = make([]Data, tt.dataLength)
			for i := 0; i < len(data); i++ {
				data[i] = &TestData{hash: makeData(byte(i))}
			}
			mt, err := New(crypto.SHA256, data)
			require.NoError(t, err)
			merklePath, err := mt.GetMerklePath(tt.dataIdxToVerify)
			require.NoError(t, err)
			rootHash, err := EvalMerklePath(merklePath, data[tt.dataIdxToVerify], crypto.SHA256)
			require.NoError(t, err)
			require.Equal(t, mt.GetRootHash(), rootHash)
		})
	}
}

func TestHibitFunction_NormalInput(t *testing.T) {
	tests := []struct {
		name string
		m    int
		n    int
	}{
		{
			name: "input zero",
			m:    0,
			n:    0,
		},
		{
			name: "input positive 1",
			m:    1,
			n:    1,
		},
		{
			name: "input positive 25",
			m:    25,
			n:    16,
		},
		{
			name: "input positive 1337",
			m:    1337,
			n:    1024,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := hibit(tt.m)
			require.Equal(t, tt.n, n)
		})
	}
}

func TestHibitFunction_NegativeInput(t *testing.T) {
	require.PanicsWithValue(t, "hibit function input cannot be negative (merkle tree input data length cannot be zero)", func() {
		hibit(-1)
	})
}

func TestHibitFunction_MaxIntDoesNotOverflow(t *testing.T) {
	n := hibit(math.MaxInt)
	require.True(t, n > 1)
}

func makeData(firstByte byte) []byte {
	data := make([]byte, 32)
	data[0] = firstByte
	return data
}

func decodeHex(s string) []byte {
	decode, _ := hex.DecodeString(s)
	return decode
}
