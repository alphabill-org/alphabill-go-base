package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ShardID_Split(t *testing.T) {
	t.Run("split empty id", func(t *testing.T) {
		empty := ShardID{}
		i0, i1 := empty.Split()
		require.NotEqual(t, empty, i0)
		require.NotEqual(t, empty, i1)
		require.NotEqual(t, i0, i1)
		require.EqualValues(t, 0, empty.Length())
		require.EqualValues(t, 1, i0.Length())
		require.EqualValues(t, 1, i1.Length())
		require.Equal(t, "0", i0.String())
		require.Equal(t, "1", i1.String())

		// must get the same ID-s as on the first split
		b0, b1 := empty.Split()
		require.Equal(t, b0, i0)
		require.Equal(t, b1, i1)
	})

	t.Run("split 7 bit id", func(t *testing.T) {
		id := ShardID{bits: []byte{0b1000_0010}, length: 7}
		i0, i1 := id.Split()
		require.NotEqual(t, id, i0)
		require.NotEqual(t, id, i1)
		require.NotEqual(t, i0, i1)
		require.EqualValues(t, 7, id.Length())
		require.EqualValues(t, 8, i0.Length())
		require.EqualValues(t, 8, i1.Length())
		require.Equal(t, "10000010", i0.String())
		require.Equal(t, "10000011", i1.String())
	})

	t.Run("split 8 bit id", func(t *testing.T) {
		id := ShardID{bits: []byte{0b1000_0001}, length: 8}
		i0, i1 := id.Split()
		require.NotEqual(t, id, i0)
		require.NotEqual(t, id, i1)
		require.NotEqual(t, i0, i1)
		require.EqualValues(t, 8, id.Length())
		require.EqualValues(t, 9, i0.Length())
		require.EqualValues(t, 9, i1.Length())
		require.Equal(t, "100000010", i0.String())
		require.Equal(t, "100000011", i1.String())
	})

	t.Run("split 9 bit id", func(t *testing.T) {
		id := ShardID{bits: []byte{0b1000_0001, 0b1000_0000}, length: 9}
		i0, i1 := id.Split()
		require.NotEqual(t, id, i0)
		require.NotEqual(t, id, i1)
		require.NotEqual(t, i0, i1)
		require.EqualValues(t, 9, id.Length())
		require.EqualValues(t, 10, i0.Length())
		require.EqualValues(t, 10, i1.Length())
		require.Equal(t, "1000000110", i0.String())
		require.Equal(t, "1000000111", i1.String())
	})
}

func Test_ShardID_Comparator(t *testing.T) {
	testCases := []struct {
		ShardID ShardID
		True    [][]byte // unit id-s belonging into the shard
		False   [][]byte // unit id-s NOT belonging into the shard
	}{
		// empty shard id
		{
			ShardID: ShardID{},
			True:    [][]byte{{0}, {1}, {0xFF}, {0, 0, 1}},
			False:   nil, // every unit id matches with empty shard id
		},
		// one bit
		{
			ShardID: ShardID{bits: []byte{0}, length: 1},
			True:    [][]byte{{0}, {1}, {0b0111_1111}},
			False:   [][]byte{{128}, {0xFF}, {0b1111_1110}},
		},
		{
			ShardID: ShardID{bits: []byte{128}, length: 1},
			True:    [][]byte{{128}, {0xFF}, {0b1111_1110}},
			False:   [][]byte{{0}, {1}, {0b0111_1111}},
		},
		// 8 bits
		{
			ShardID: ShardID{bits: []byte{0}, length: 8},
			True:    [][]byte{{0}, {0, 0}, {0, 1}, {0, 0xFF}},
			False:   [][]byte{{1}, {128}, {0xFF}, {1, 0}, {128, 0}},
		},
		{
			ShardID: ShardID{bits: []byte{0xFF}, length: 8},
			True:    [][]byte{{0xFF}, {0xFF, 0}, {0xFF, 0xFF}},
			False:   [][]byte{{0}, {1}, {128}, {0xFE}, {0xEF}, {0, 0xFF}, {128, 0}},
		},
		// 9..15 bits
		{
			ShardID: ShardID{bits: []byte{0, 0}, length: 9},
			True:    [][]byte{{0, 0}, {0, 1}, {0, 0b0111_1111}},
			False:   [][]byte{{0, 128}, {0, 0xFF}, {1, 0}, {128, 0}},
		},
		{
			ShardID: ShardID{bits: []byte{0, 0}, length: 15},
			True:    [][]byte{{0, 0}, {0, 1}, {0, 1, 0xFF}},
			False:   [][]byte{{0, 128}, {0, 0xFF}, {1, 0}, {128, 0}, {0, 0b0000_0010}},
		},
		// 16 bits
		{
			ShardID: ShardID{bits: []byte{0xFF, 0}, length: 16},
			True:    [][]byte{{0xFF, 0}, {0xFF, 0, 0xFF}},
			False:   [][]byte{{0, 0xFF}, {0, 0xFF, 0}, {0xFF, 1}, {0xFF, 128}},
		},
		// over 16 bits
		{
			ShardID: ShardID{bits: []byte{0xFF, 0, 128}, length: 17},
			True:    [][]byte{{0xFF, 0, 128}, {0xFF, 0, 0xFF}, {0xFF, 0, 0xF0}},
			False:   [][]byte{{0, 0xFF, 128}, {128, 0xFF, 0}, {0xFF, 1, 128}, {0xFF, 128, 0}},
		},
		{
			ShardID: ShardID{bits: []byte{0xFF, 0, 128, 1}, length: 32},
			True:    [][]byte{{0xFF, 0, 128, 1}, {0xFF, 0, 128, 1, 0}, {0xFF, 0, 128, 1, 0xFF}},
			False:   [][]byte{{0xFF, 0, 128, 2}, {0xFF, 0, 128, 128}, {0xFE, 0, 128, 1}},
		},
		{
			ShardID: ShardID{bits: []byte{0xFF, 0, 0, 1, 0b010_0_0000}, length: 35},
			True:    [][]byte{{0xFF, 0, 0, 1, 0b010_0_0011}, {0xFF, 0, 0, 1, 0b010_1_0011, 0xFF}},
			False:   [][]byte{{0xFF, 0, 0, 1, 0b011_0_0000}, {0xFF, 0, 0, 0, 0b010_0_0000}, {0xEF, 0, 0, 1, 0b010_0_0000}},
		},
	}

	for tn, tc := range testCases {
		cf := tc.ShardID.Comparator()

		for x, uid := range tc.True {
			if !cf(uid) {
				t.Errorf("[%d] expected True[%d] for shard id %q", tn, x, tc.ShardID)
			}
		}

		for x, uid := range tc.False {
			if cf(uid) {
				t.Errorf("[%d] expected False[%d] for shard id %q", tn, x, tc.ShardID)
			}
		}
	}
}

func Test_ShardID_String(t *testing.T) {
	testCases := []struct {
		bits []byte
		len  uint   // number of bits in use in "bits"
		str  string // expected output
	}{
		{len: 0, bits: nil, str: ""},
		{len: 0, bits: []byte{}, str: ""},
		{len: 1, bits: []byte{0}, str: "0"},
		{len: 1, bits: []byte{128}, str: "1"},
		{len: 2, bits: []byte{0b1000_0000}, str: "10"},
		{len: 7, bits: []byte{0}, str: "0000000"},
		{len: 8, bits: []byte{0}, str: "00000000"},
		{len: 8, bits: []byte{1}, str: "00000001"},
		{len: 8, bits: []byte{128}, str: "10000000"},
		{len: 9, bits: []byte{1, 128}, str: "000000011"},
		{len: 9, bits: []byte{0b1000_0000, 128}, str: "100000001"},
		{len: 12, bits: []byte{0b0101_1010, 0b1111_0000}, str: "010110101111"},
		{len: 16, bits: []byte{0xFF, 0}, str: "1111111100000000"},
	}

	for x, tc := range testCases {
		if out := (ShardID{bits: tc.bits, length: tc.len}).String(); tc.str != out {
			t.Errorf("[%d] expected %q got %q", x, tc.str, out)
		}
	}
}

func Test_ShardID_MarshalText(t *testing.T) {
	t.Run("invalid hex input", func(t *testing.T) {
		id := ShardID{}
		err := id.UnmarshalText([]byte("0xA"))
		require.EqualError(t, err, `decoding from hex: hex string of odd length`)
	})

	t.Run("invalid bitstring encoding", func(t *testing.T) {
		id := ShardID{}
		err := id.UnmarshalText([]byte("0x0000"))
		require.EqualError(t, err, `decoding bitstring: invalid bit string encoding: last byte doesn't contain end marker`)
	})

	t.Run("Yellowpaper example", func(t *testing.T) {
		id := ShardID{bits: []byte{0b0101_1010, 0b1111_0000}, length: 12}
		b, err := id.MarshalText()
		require.NoError(t, err)
		require.EqualValues(t, "0x5af8", b)

		id2 := ShardID{}
		require.NoError(t, id2.UnmarshalText(b))
		require.Equal(t, id, id2)
	})
}

func Test_ShardID_MarshalCBOR(t *testing.T) {
	t.Run("empty id", func(t *testing.T) {
		id := ShardID{}
		b, err := Cbor.Marshal(id)
		require.NoError(t, err)
		// empty shard id is encoded as one byte end marker 0b1000_0000
		require.EqualValues(t, []byte{0x41, 0x80}, b)

		var id2 ShardID
		require.NoError(t, Cbor.Unmarshal(b, &id2))
		require.Equal(t, id, id2)
		require.True(t, id.Equal(id2))
	})

	t.Run("example from YP", func(t *testing.T) {
		id := ShardID{bits: []byte{0b0101_1010, 0b1111_0000}, length: 12}
		b, err := Cbor.Marshal(id)
		require.NoError(t, err)
		require.EqualValues(t, []byte{0x42, 0x5a, 0xf8}, b)

		var id2 ShardID
		require.NoError(t, Cbor.Unmarshal(b, &id2))
		require.Equal(t, id, id2)
		require.True(t, id.Equal(id2))
	})

	t.Run("shard id as part of some struct", func(t *testing.T) {
		type foo struct {
			_  struct{} `cbor:",toarray"`
			ID ShardID
			V  int
		}

		id := ShardID{bits: []byte{0b0101_1010, 0b1111_0000}, length: 16}
		v := foo{ID: id, V: 10000}
		b, err := Cbor.Marshal(v)
		require.NoError(t, err)

		v2 := foo{}
		require.NoError(t, Cbor.Unmarshal(b, &v2))
		require.Equal(t, v, v2)
		require.True(t, id.Equal(v2.ID))
	})
}

func Test_ShardID_Key(t *testing.T) {
	t.Run("zero value", func(t *testing.T) {
		idN := ShardID{}
		idE := ShardID{bits: []byte{}, length: 0}
		require.Equal(t, idN.Key(), idE.Key())
	})

	t.Run("different length of zero bits", func(t *testing.T) {
		id1 := ShardID{bits: []byte{0}, length: 1}
		id2 := ShardID{bits: []byte{0}, length: 2}
		id8 := ShardID{bits: []byte{0}, length: 8}
		require.NotEqual(t, id1.Key(), id2.Key())
		require.NotEqual(t, id1.Key(), id8.Key())
		require.NotEqual(t, id2.Key(), id8.Key())
	})

	t.Run("text marshaling", func(t *testing.T) {
		// after marshal -> unmarshal must produce the same key
		var idA, idB ShardID
		buf, err := idA.MarshalText()
		require.NoError(t, err)
		require.NoError(t, idB.UnmarshalText(buf))
		require.Equal(t, idA.Key(), idB.Key())

		// non empty ID
		idA0, idA1 := idA.Split()
		buf, err = idA0.MarshalText()
		require.NoError(t, err)
		require.NoError(t, idB.UnmarshalText(buf))
		require.Equal(t, idA0.Key(), idB.Key())
		require.NotEqual(t, idA0.Key(), idA1.Key())
		require.NotEqual(t, idA0.Key(), idA.Key())

		buf, err = idA1.MarshalText()
		require.NoError(t, err)
		require.NoError(t, idB.UnmarshalText(buf))
		require.Equal(t, idA1.Key(), idB.Key())
	})

	t.Run("CBOR marshaling", func(t *testing.T) {
		// after marshal -> unmarshal must produce the same key
		var idA, idB ShardID
		buf, err := idA.MarshalCBOR()
		require.NoError(t, err)
		require.NoError(t, idB.UnmarshalCBOR(buf))
		require.Equal(t, idA.Key(), idB.Key())

		// non empty ID
		idA0, idA1 := idA.Split()
		buf, err = idA0.MarshalCBOR()
		require.NoError(t, err)
		require.NoError(t, idB.UnmarshalCBOR(buf))
		require.Equal(t, idA0.Key(), idB.Key())
		require.NotEqual(t, idA0.Key(), idA1.Key())
		require.NotEqual(t, idA0.Key(), idA.Key())

		buf, err = idA1.MarshalCBOR()
		require.NoError(t, err)
		require.NoError(t, idB.UnmarshalCBOR(buf))
		require.Equal(t, idA1.Key(), idB.Key())
	})
}
