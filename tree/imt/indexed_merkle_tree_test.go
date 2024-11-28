package imt

import (
	"crypto"
	"fmt"
	"testing"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/util"
	"github.com/stretchr/testify/require"
)

type TestData struct {
	key  []byte
	data byte
}

func (t TestData) AddToHasher(hasher abhash.Hasher) {
	hasher.WriteRaw([]byte{t.data})
}

func (t TestData) Key() []byte {
	return t.key
}

func TestNewIMTWithNilData(t *testing.T) {
	var data []LeafData = nil
	imt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, imt)
	require.EqualValues(t, "────┤ empty", imt.PrettyPrint())
	require.Nil(t, imt.GetRootHash())
	require.Equal(t, 0, imt.dataLength)
	path, err := imt.GetMerklePath([]byte{0})
	require.EqualError(t, err, "tree is empty")
	require.Nil(t, path)
	var merklePath []*PathItem = nil
	treeHash, err := IndexTreeOutput(merklePath, []byte{0}, crypto.SHA256)
	require.ErrorIs(t, err, ErrTreeEmpty)
	require.Nil(t, treeHash)
}

func TestNewIMTWithEmptyData(t *testing.T) {
	imt, err := New(crypto.SHA256, []LeafData{})
	require.NoError(t, err)
	require.NotNil(t, imt)
	require.Nil(t, imt.GetRootHash())
	require.Equal(t, 0, imt.dataLength)
	path, err := imt.GetMerklePath([]byte{0})
	require.EqualError(t, err, "tree is empty")
	require.Nil(t, path)
	var merklePath []*PathItem
	treeHash, err := IndexTreeOutput(merklePath, []byte{0}, crypto.SHA256)
	require.ErrorIs(t, err, ErrTreeEmpty)
	require.Nil(t, treeHash)
}

func TestNewIMTWithSingleNode(t *testing.T) {
	data := []LeafData{
		&TestData{
			key:  []byte{0, 0, 0, 0},
			data: 1,
		},
	}
	imt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, imt)
	require.NotNil(t, imt.GetRootHash())
	hasher := abhash.New(crypto.SHA256.New())
	data[0].AddToHasher(hasher)
	dataHash, err := hasher.Sum()
	require.NoError(t, err)
	hasher.Reset()
	hasher.Write([]byte{tagLeaf})
	hasher.Write(data[0].Key())
	hasher.Write(dataHash)
	h, err := hasher.Sum()
	require.NoError(t, err)
	require.Equal(t, h, imt.GetRootHash())
	path, err := imt.GetMerklePath(data[0].Key())
	require.NoError(t, err)
	h2, err := IndexTreeOutput(path, data[0].Key(), crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, h2, imt.GetRootHash())
}

func TestNewIMTUnsortedInput(t *testing.T) {
	var data = []LeafData{
		&TestData{
			key:  util.Uint32ToBytes(uint32(3)),
			data: 3,
		},
		&TestData{
			key:  util.Uint32ToBytes(uint32(1)),
			data: 1,
		},
	}
	imt, err := New(crypto.SHA256, data)
	require.EqualError(t, err, "data is not sorted by key in strictly ascending order")
	require.Nil(t, imt)
}

func TestNewIMTEqualIndexValues(t *testing.T) {
	var data = []LeafData{
		&TestData{
			key:  util.Uint32ToBytes(uint32(1)),
			data: 1,
		},
		&TestData{
			key:  util.Uint32ToBytes(uint32(3)),
			data: 3,
		},
		&TestData{
			key:  util.Uint32ToBytes(uint32(3)),
			data: 3,
		},
	}
	imt, err := New(crypto.SHA256, data)
	require.EqualError(t, err, "data is not sorted by key in strictly ascending order")
	require.Nil(t, imt)
}

func TestNewIMTYellowpaperExample(t *testing.T) {
	var data = []LeafData{
		&TestData{
			key:  []byte{1},
			data: 1,
		},
		&TestData{
			key:  []byte{3},
			data: 3,
		},
		&TestData{
			key:  []byte{7},
			data: 7,
		},
		&TestData{
			key:  []byte{9},
			data: 9,
		},
		&TestData{
			key:  []byte{10},
			data: 10,
		},
	}
	imt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, imt)
	require.EqualValues(t, "9D5EB6D41E8588BC7620841538AE510C5D15AFAD5A40AE4248FC017A5369BB2A", fmt.Sprintf("%X", imt.GetRootHash()))
	/* See Yellowpaper appendix C.2.1 Figure 32. Keys of the nodes of an indexed hash tree.
			┌──key: 0a, AFFD74304EBDDC98E2EE9104CEF58FA98BCA7242406D3E3B7816C0E8DB5678E5
		┌──key: 09, B717C4B888BF5B1D9B47636DC8426F15C349DBA0D28437700C5B2AACA0E11C60
		│	└──key: 09, 3BF2CF4FEE1823F5150CACCAF75CB03721CEE98AF6DE0338EDF59E2B906DB687
	┌──key: 07, 9D5EB6D41E8588BC7620841538AE510C5D15AFAD5A40AE4248FC017A5369BB2A
	│	│	┌──key: 07, C543D5DB839DDE7F3B5C98B7BCCC2AF7B967EFB979A04AC17E731B86869ED321
	│	└──key: 03, DB8F6CD9959973E88079FFE6822455393DD3BB05B99879E4136A5CFB4CD60A34
	│		│	┌──key: 03, FB04FC67680053F4F78D78662937D9935D4491C868C3158AA5C754EC3527CAA4
	│		└──key: 01, 0B9FF05CCE9EE9E80AF558FFAA6C360F575DA1993F948929E81AF4EC718AE49F
	│			└──key: 01, 662D89D82F15CD2DDFDCCCB221C9360636397BF0066A9F67D5A81551F7FD9C1F
	*/
	treeStr := "\t\t┌──key: 0a, AFFD74304EBDDC98E2EE9104CEF58FA98BCA7242406D3E3B7816C0E8DB5678E5\n\t┌──key: 09, B717C4B888BF5B1D9B47636DC8426F15C349DBA0D28437700C5B2AACA0E11C60\n\t│\t└──key: 09, 3BF2CF4FEE1823F5150CACCAF75CB03721CEE98AF6DE0338EDF59E2B906DB687\n┌──key: 07, 9D5EB6D41E8588BC7620841538AE510C5D15AFAD5A40AE4248FC017A5369BB2A\n│\t│\t┌──key: 07, C543D5DB839DDE7F3B5C98B7BCCC2AF7B967EFB979A04AC17E731B86869ED321\n│\t└──key: 03, DB8F6CD9959973E88079FFE6822455393DD3BB05B99879E4136A5CFB4CD60A34\n│\t\t│\t┌──key: 03, FB04FC67680053F4F78D78662937D9935D4491C868C3158AA5C754EC3527CAA4\n│\t\t└──key: 01, 0B9FF05CCE9EE9E80AF558FFAA6C360F575DA1993F948929E81AF4EC718AE49F\n│\t\t\t└──key: 01, 662D89D82F15CD2DDFDCCCB221C9360636397BF0066A9F67D5A81551F7FD9C1F\n"
	require.Equal(t, treeStr, imt.PrettyPrint())
	// check tree node key values
	for _, d := range data {
		path, err := imt.GetMerklePath(d.Key())
		require.NoError(t, err)
		h, err := IndexTreeOutput(path, d.Key(), crypto.SHA256)
		require.NoError(t, err)
		require.EqualValues(t, h, imt.GetRootHash())
		// verify data hash
		hasher := crypto.SHA256.New()
		abhasher := abhash.New(hasher)
		d.AddToHasher(abhasher)
		require.EqualValues(t, hasher.Sum(nil), path[0].Hash)
	}
	// test non-inclusion
	idx := []byte{8}
	path, err := imt.GetMerklePath(idx)
	require.NoError(t, err)
	require.NotEqualValues(t, idx, path[0].Key)
	// path still evaluates to root hash
	h, err := IndexTreeOutput(path, idx, crypto.SHA256)
	require.NoError(t, err)
	require.EqualValues(t, h, imt.GetRootHash())
}

func TestNewIMTWithOddNumberOfLeaves(t *testing.T) {
	var data = make([]LeafData, 5)
	for i := 0; i < len(data); i++ {
		data[i] = &TestData{
			key:  util.Uint32ToBytes(uint32(i)),
			data: byte(i),
		}
	}
	imt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, imt)
	require.EqualValues(t, "2F6436F5C63FEEFF031CF8176434B4AD89B78C6B39218A262F1B36FB8A2FF1A1", fmt.Sprintf("%X", imt.GetRootHash()))
	require.NotEmpty(t, imt.PrettyPrint())
	// check the hash chain of all key nodes
	for _, d := range data {
		path, err := imt.GetMerklePath(d.Key())
		require.NoError(t, err)
		h, err := IndexTreeOutput(path, d.Key(), crypto.SHA256)
		require.NoError(t, err)
		require.EqualValues(t, h, imt.GetRootHash())
		// verify data hash
		hasher := crypto.SHA256.New()
		abhasher := abhash.New(hasher)
		d.AddToHasher(abhasher)
		require.EqualValues(t, hasher.Sum(nil), path[0].Hash)
	}
	// non-inclusion
	leaf := TestData{
		key:  util.Uint32ToBytes(uint32(9)),
		data: 9,
	}
	path, err := imt.GetMerklePath(leaf.Key())
	require.NoError(t, err)
	h, err := IndexTreeOutput(path, leaf.Key(), crypto.SHA256)
	require.NoError(t, err)
	require.EqualValues(t, h, imt.GetRootHash())
	// however, it is not from index 9
	require.NotEqualValues(t, leaf.key, path[0].Key)
	hasher := crypto.SHA256.New()
	abhasher := abhash.New(hasher)
	leaf.AddToHasher(abhasher)
	require.NotEqualValues(t, hasher.Sum(nil), path[0].Hash)
}

func TestNewIMTWithEvenNumberOfLeaves(t *testing.T) {
	var data = make([]LeafData, 8)
	for i := 0; i < len(data); i++ {
		data[i] = &TestData{
			key:  util.Uint32ToBytes(uint32(i)),
			data: byte(i),
		}
	}
	imt, err := New(crypto.SHA256, data)
	require.NoError(t, err)
	require.NotNil(t, imt)
	require.EqualValues(t, "E88F7B394C21D899B725F3CB0134D1EB8003E8C5E03F4D766D523F2BC5A05C25", fmt.Sprintf("%X", imt.GetRootHash()))
	require.NotEmpty(t, imt.PrettyPrint())
	// check the hash chain of all key nodes
	for _, d := range data {
		path, err := imt.GetMerklePath(d.Key())
		require.NoError(t, err)
		h, err := IndexTreeOutput(path, d.Key(), crypto.SHA256)
		require.NoError(t, err)
		require.EqualValues(t, h, imt.GetRootHash())
	}
	// non-inclusion
	leaf := TestData{
		key:  util.Uint32ToBytes(uint32(9)),
		data: byte(9),
	}
	path, err := imt.GetMerklePath(leaf.Key())
	require.NoError(t, err)

	h, err := IndexTreeOutput(path, leaf.Key(), crypto.SHA256)
	require.NoError(t, err)
	require.EqualValues(t, h, imt.GetRootHash())
	// however, it is not from index 9
	require.NotEqualValues(t, leaf.key, path[0].Key)
	hasher := crypto.SHA256.New()
	abhasher := abhash.New(hasher)
	leaf.AddToHasher(abhasher)
	require.NotEqualValues(t, hasher.Sum(nil), path[0].Hash)
}
