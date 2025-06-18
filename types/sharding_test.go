package types

import (
	cryptoRnd "crypto/rand"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alphabill-org/alphabill-go-base/cbor"
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

		err = id.UnmarshalText([]byte(""))
		require.EqualError(t, err, `decoding bitstring: invalid bit string encoding: empty input`)
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
		b, err := cbor.Marshal(id)
		require.NoError(t, err)
		// empty shard id is encoded as one byte end marker 0b1000_0000
		require.EqualValues(t, []byte{0x41, 0x80}, b)

		var id2 ShardID
		require.NoError(t, cbor.Unmarshal(b, &id2))
		require.Equal(t, id, id2)
		require.True(t, id.Equal(id2))
	})

	t.Run("example from YP", func(t *testing.T) {
		id := ShardID{bits: []byte{0b0101_1010, 0b1111_0000}, length: 12}
		b, err := cbor.Marshal(id)
		require.NoError(t, err)
		require.EqualValues(t, []byte{0x42, 0x5a, 0xf8}, b)

		var id2 ShardID
		require.NoError(t, cbor.Unmarshal(b, &id2))
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
		b, err := cbor.Marshal(v)
		require.NoError(t, err)

		v2 := foo{}
		require.NoError(t, cbor.Unmarshal(b, &v2))
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

func Test_ShardingScheme_All(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		// invalid tree with only "0" child ("1" is missing)
		scheme := buildShardingScheme([]ShardID{{bits: []byte{0}, length: 1}})
		require.Panics(t, func() { _ = slices.Collect(scheme.All()) })
	})

	t.Run("expected shards", func(t *testing.T) {
		// manually build sharding scheme and verify that we get expected IDs
		var sc ShardingScheme
		var emptyID ShardID
		require.Equal(t, []ShardID{emptyID}, slices.Collect(sc.All()))

		id0, id1, err := sc.Split(emptyID)
		require.NoError(t, err)
		require.ElementsMatch(t, []ShardID{id0, id1}, slices.Collect(sc.All()))

		id00, id01, err := sc.Split(id0)
		require.NoError(t, err)
		require.ElementsMatch(t, []ShardID{id00, id01, id1}, slices.Collect(sc.All()))

		id10, id11, err := sc.Split(id1)
		require.NoError(t, err)
		require.ElementsMatch(t, []ShardID{id00, id01, id10, id11}, slices.Collect(sc.All()))

		id100, id101, err := sc.Split(id10)
		require.NoError(t, err)
		require.ElementsMatch(t, []ShardID{id00, id01, id100, id101, id11}, slices.Collect(sc.All()))
	})
}

func Test_ShardingScheme_Split(t *testing.T) {
	t.Run("invalid split", func(t *testing.T) {
		var scheme ShardingScheme
		_, _, err := scheme.Split(ShardID{bits: []byte{0}, length: 1})
		require.EqualError(t, err, `shard ID 0 is not in the scheme`)

		_, _, err = scheme.Split(ShardID{})
		require.NoError(t, err)
		// empty ID is no longer root, can't split it again
		_, _, err = scheme.Split(ShardID{})
		require.EqualError(t, err, `shard ID  is not a leaf`)
	})

	t.Run("split random", func(t *testing.T) {
		// start with empty scheme and keep splitting random ID until certain number of
		// shards is reached. Each split should add one shard (we replace one existing
		//  with two new ones so total increases by one)
		var sc ShardingScheme
		for count := 1; count < 40; count++ {
			require.NoError(t, sc.IsValid())
			ids := slices.Collect(sc.All())
			require.Equal(t, count, len(ids))

			id := ids[rand.Int32N(int32(len(ids)))]
			_, _, err := sc.Split(id)
			require.NoError(t, err)
		}
	})
}

func Test_ShardingScheme_Merge(t *testing.T) {
	emptyID := ShardID{}
	id0, id1 := emptyID.Split()
	id00, id01 := id0.Split()
	id10, id11 := id1.Split()
	id100, id101 := id10.Split()
	// full tree: [00 0 01 ⌊⌋ 100 10 101 1 11]
	// leafs: [00 01 100 101 11]
	scheme, err := NewShardingScheme([]ShardID{id00, id0, id01, emptyID, id100, id10, id101, id1, id11})
	require.NoError(t, err)
	require.NoError(t, scheme.IsValid())

	// leaf nodes can't be merged
	for id := range scheme.All() {
		require.EqualError(t, scheme.Merge(id), fmt.Sprintf("node %s is a leaf", id))
	}

	// node which is not a parent of leafs can't be merged
	for _, id := range []ShardID{emptyID, id1} {
		require.EqualError(t, scheme.Merge(id), fmt.Sprintf("child 0 of the %s is not a leaf", id))
	}

	// unknown ID
	require.EqualError(t, scheme.Merge(ShardID{bits: []byte{0}, length: 8}), `shard ID 00000000 is not in the scheme`)

	// correct order to merge the tree back into single shard
	for _, id := range []ShardID{id0, id10, id1, emptyID} {
		require.NoError(t, scheme.Merge(id))
	}
	require.Equal(t, []ShardID{emptyID}, slices.Collect(scheme.All()), "expected empty scheme after merges")
}

func Test_ShardingScheme_findNode(t *testing.T) {
	emptyID := ShardID{}
	id0, id1 := emptyID.Split()
	id10, id11 := id1.Split()

	var sc ShardingScheme
	// empty scheme contains empty ID...
	node, err := sc.findNode(emptyID)
	require.NoError(t, err)
	require.NotNil(t, node)
	require.True(t, emptyID.Equal(node.id))
	// ...and no other IDs
	node, err = sc.findNode(id0)
	require.EqualError(t, err, `shard ID 0 is not in the scheme`)
	require.Nil(t, node)
	node, err = sc.findNode(id1)
	require.EqualError(t, err, `shard ID 1 is not in the scheme`)
	require.Nil(t, node)
	node, err = sc.findNode(id10)
	require.EqualError(t, err, `shard ID 10 is not in the scheme`)
	require.Nil(t, node)

	// add shards "0" and "1" into the scheme
	_, _, err = sc.Split(emptyID)
	require.NoError(t, err)

	node, err = sc.findNode(emptyID)
	require.NoError(t, err)
	require.NotNil(t, node)
	require.True(t, emptyID.Equal(node.id))

	node, err = sc.findNode(id0)
	require.NoError(t, err)
	require.NotNil(t, node)
	require.True(t, id0.Equal(node.id))

	node, err = sc.findNode(id1)
	require.NoError(t, err)
	require.NotNil(t, node)
	require.True(t, id1.Equal(node.id))
	// but no other IDs
	node, err = sc.findNode(id10)
	require.EqualError(t, err, `shard ID 10 is not in the scheme`)
	require.Nil(t, node)
	node, err = sc.findNode(id11)
	require.EqualError(t, err, `shard ID 11 is not in the scheme`)
	require.Nil(t, node)
}

func Test_ShardingScheme_IsValid(t *testing.T) {
	emptyID := ShardID{}
	id0, id1 := emptyID.Split()
	id00, id01 := id0.Split()
	id10, id11 := id1.Split()
	id100, id101 := id10.Split()

	t.Run("invalid - invalid tree", func(t *testing.T) {
		/*** unexpected id length ***/
		// root node must have empty ID, ie length == 0
		scheme := ShardingScheme{}
		scheme.id = id0
		require.EqualError(t, scheme.IsValid(), `expected shard ID length to be 0 bits, got 1 (0)`)

		// set empty id on level 1
		scheme = ShardingScheme{}
		_, _, err := scheme.Split(emptyID)
		require.NoError(t, err)
		// schema is now [0 1], set node 1 ID to empty ID
		scheme.next1.id = emptyID
		require.EqualError(t, scheme.IsValid(), `expected shard ID length to be 1 bits, got 0 ()`)

		/*** correct length but unexpected ID ***/
		scheme = ShardingScheme{}
		_, _, err = scheme.Split(emptyID)
		require.NoError(t, err)
		scheme.next1.id = id0 // replace "1" with "0"
		require.EqualError(t, scheme.IsValid(), `expected bit 0 to be 1, got 0 (0)`)
	})

	t.Run("invalid - no sibling", func(t *testing.T) {
		// cases where the shard tree is not "balanced" meaning scheme is not prefix free
		var testCases = []struct {
			scheme ShardingScheme
			errMsg string
		}{
			{scheme: buildShardingScheme([]ShardID{id0}), errMsg: `shard ID "0" has no sibling`},
			{scheme: buildShardingScheme([]ShardID{id1}), errMsg: `shard ID "1" has no sibling`},
			{scheme: buildShardingScheme([]ShardID{id00, id01, id0}), errMsg: `shard ID "0" has no sibling`},
			{scheme: buildShardingScheme([]ShardID{id00, id1, id0}), errMsg: `shard ID "00" has no sibling`},
			{scheme: buildShardingScheme([]ShardID{id01, id1, id0}), errMsg: `shard ID "01" has no sibling`},
		}

		for i, tc := range testCases {
			err := tc.scheme.IsValid()
			if err == nil {
				t.Errorf("[%d] expected error\n%s\nfor scheme %v", i, tc.errMsg, tc.scheme)
				continue
			}
			if err.Error() != tc.errMsg {
				t.Errorf("[%d] expected error\n%s\ngot\n%v", i, tc.errMsg, err)
			}
		}
	})

	t.Run("valid", func(t *testing.T) {
		var testCases = []ShardingScheme{
			{},
			buildShardingScheme([]ShardID{emptyID}),
			buildShardingScheme([]ShardID{id0, id1}),
			buildShardingScheme([]ShardID{id00, id01, id1}),
			buildShardingScheme([]ShardID{id00, id01, id10, id11}),
			buildShardingScheme([]ShardID{id00, id01, id100, id101, id11}),
		}

		for i, tc := range testCases {
			if err := tc.IsValid(); err != nil {
				t.Errorf("[%d] unexpected error: %v", i, err)
			}
		}
	})
}

func Test_ShardingScheme_Shard(t *testing.T) {
	pdr := PartitionDescriptionRecord{
		TypeIDLen: 8,
		UnitIDLen: 7 * 8,
	}

	prnd := func(buf []byte) error {
		_, err := cryptoRnd.Read(buf)
		return err
	}

	// record ID-s we split for debugging
	splitPoints := []ShardID{}
	// start with empty scheme
	scheme := ShardingScheme{}

	for maxLen := uint(0); maxLen < 20; {
		if !assert.NoError(t, scheme.IsValid()) {
			t.Fatalf("splits: %v", splitPoints)
		}

		shards := slices.Collect(scheme.All())
		for _, sid := range shards {
			uid, err := pdr.ComposeUnitID(sid, 0, prnd)
			require.NoError(t, err)
			out := scheme.Shard(uid)
			require.True(t, out.Equal(sid), "expected shard ID %q got %q from unit ID %x", sid, out, uid)
		}

		// split random shard
		sid := shards[rand.Int32N(int32(len(shards)))]
		splitPoints = append(splitPoints, sid)
		if sid.Length() >= maxLen {
			maxLen = sid.Length() + 1
		}
		_, _, err := scheme.Split(sid)
		if !assert.NoError(t, err) {
			t.Fatalf("splits: %v", splitPoints)
		}
	}
}

func Test_ShardingScheme_MarshalCBOR(t *testing.T) {
	t.Run("expected output", func(t *testing.T) {
		// compare some simple cases against hardcoded result
		// empty scheme
		scheme := ShardingScheme{}
		b, err := scheme.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, []byte{0x81, 0x41, 0x80}, b)

		// scheme with two IDs: 0 & 1
		_, _, err = scheme.Split(ShardID{})
		require.NoError(t, err)
		b, err = scheme.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, []byte{0x82, 0x41, 0x40, 0x41, 0xc0}, b)
	})

	t.Run("marshal roundtrip", func(t *testing.T) {
		// modify scheme by splitting random shard (until certain length
		// of shard ID) and see do we get back the same scheme after
		// serialization roundtrip
		scheme := ShardingScheme{}
		for maxLen := uint(0); maxLen < 20; {
			shards := slices.Collect(scheme.All())
			b, err := scheme.MarshalCBOR()
			require.NoError(t, err)

			var out ShardingScheme
			require.NoError(t, out.UnmarshalCBOR(b))
			require.ElementsMatch(t, shards, slices.Collect(out.All()))

			// split random shard
			sid := shards[rand.Int32N(int32(len(shards)))]
			if sid.Length() >= maxLen {
				maxLen = sid.Length() + 1
			}
			_, _, err = scheme.Split(sid)
			assert.NoError(t, err)
		}
	})
}

func Test_CompareShardIDs(t *testing.T) {
	emptyID := ShardID{}
	id0, id1 := emptyID.Split()
	id00, id01 := id0.Split()
	id10, id11 := id1.Split()
	id100, id101 := id10.Split()

	// verify that the first ID is smaller than the second one
	checkOrder := func(t *testing.T, a, b ShardID) {
		require.Less(t, CompareShardIDs(a, b), 0, "%s\n%s", a, b)
		require.Greater(t, CompareShardIDs(b, a), 0, "%s\n%s", b, a)
	}

	t.Run("equal", func(t *testing.T) {
		check := func(id ShardID) {
			require.Zero(t, CompareShardIDs(id, id))
		}

		require.Zero(t, CompareShardIDs(emptyID, emptyID))
		require.Zero(t, CompareShardIDs(id0, id0))
		require.Zero(t, CompareShardIDs(id1, id1))
		require.Zero(t, CompareShardIDs(id00, id00))
		require.Zero(t, CompareShardIDs(id10, id10))
		require.Zero(t, CompareShardIDs(id101, id101))

		check(ShardID{bits: []byte{0}, length: 7})
		check(ShardID{bits: []byte{0xFE}, length: 7})
		check(ShardID{bits: []byte{0}, length: 8})
		check(ShardID{bits: []byte{1}, length: 8})
		check(ShardID{bits: []byte{0xFF}, length: 8})
		check(ShardID{bits: []byte{0, 0}, length: 9})
		check(ShardID{bits: []byte{0xFF, 0x80}, length: 9})
		check(ShardID{bits: []byte{0x50, 0, 0xFF, 0}, length: 31})
		check(ShardID{bits: []byte{0xE0, 0, 0, 0x0F}, length: 32})
		check(ShardID{bits: []byte{0xFF, 0xFF, 0xFF, 0xFF}, length: 32})
		check(ShardID{bits: []byte{0xFF, 0, 0, 0, 0x80}, length: 33})
	})

	t.Run("compare with empty", func(t *testing.T) {
		// 0 < ⌊⌋ < 1
		checkOrder(t, id0, emptyID)
		checkOrder(t, emptyID, id1)

		// any id starting with "1" is greater than empty ID (IOW emptyID < "1...")
		checkOrder(t, emptyID, id11)
		checkOrder(t, emptyID, ShardID{bits: []byte{0b1000_0000}, length: 7})
		checkOrder(t, emptyID, ShardID{bits: []byte{0xFF}, length: 8})
		checkOrder(t, emptyID, ShardID{bits: []byte{0b1000_0001}, length: 8})
		checkOrder(t, emptyID, ShardID{bits: []byte{0b1000_0000, 0}, length: 9})
		checkOrder(t, emptyID, ShardID{bits: []byte{0b1000_0000, 0, 0, 0}, length: 31})
		checkOrder(t, emptyID, ShardID{bits: []byte{0b1000_0000, 0, 0, 0}, length: 32})
		checkOrder(t, emptyID, ShardID{bits: []byte{0b1000_0000, 0, 0, 0, 0}, length: 33})

		// any id starting with "0" is less than empty ID (IOW emptyID > "0...")
		checkOrder(t, id00, emptyID)
		checkOrder(t, ShardID{bits: []byte{0}, length: 7}, emptyID)
		checkOrder(t, ShardID{bits: []byte{0}, length: 8}, emptyID)
		checkOrder(t, ShardID{bits: []byte{0b0000_0001}, length: 8}, emptyID)
		checkOrder(t, ShardID{bits: []byte{0b0111_1111}, length: 8}, emptyID)
		checkOrder(t, ShardID{bits: []byte{0b0111_1111, 0x80}, length: 9}, emptyID)
		checkOrder(t, ShardID{bits: []byte{0b0111_1111, 0xFF, 0xFF, 0xFE}, length: 31}, emptyID)
		checkOrder(t, ShardID{bits: []byte{0b0111_1111, 0xFF, 0xFF, 0xFF}, length: 32}, emptyID)
		checkOrder(t, ShardID{bits: []byte{0b0111_1111, 0xFF, 0xFF, 0xFF, 0x80}, length: 33}, emptyID)
	})

	t.Run("compare two non-empty IDs", func(t *testing.T) {
		// verify that a < b < c
		compareTriple := func(a, b, c ShardID) {
			require.Less(t, CompareShardIDs(a, b), 0, "%s\n%s", a, b)
			require.Greater(t, CompareShardIDs(b, a), 0, "%s\n%s", b, a)
			require.Less(t, CompareShardIDs(b, c), 0, "%s\n%s", b, c)
			require.Greater(t, CompareShardIDs(c, b), 0, "%s\n%s", c, b)
			require.Less(t, CompareShardIDs(a, c), 0, "%s\n%s", a, c)
			require.Greater(t, CompareShardIDs(c, a), 0, "%s\n%s", c, a)
		}

		checkOrder(t, id0, id01)
		checkOrder(t, id0, id1)
		checkOrder(t, id0, id10)
		checkOrder(t, id0, id100)
		checkOrder(t, id00, id0)
		checkOrder(t, id00, id01)
		checkOrder(t, id00, id1)
		checkOrder(t, id00, id10)
		checkOrder(t, id00, id100)
		checkOrder(t, ShardID{bits: []byte{0, 0, 0, 0, 0}, length: 33}, id0)

		idA := ShardID{bits: []byte{0xFF, 0xFF, 0xFF, 0xFE}, length: 32}
		idB := ShardID{bits: []byte{0xFF, 0xFF, 0xFF, 0xFF}, length: 32}
		checkOrder(t, idA, idB)
		idA = ShardID{bits: []byte{0x7F, 0xFF, 0xFF, 0xFF}, length: 32}
		checkOrder(t, idA, idB)
		idA = ShardID{bits: []byte{0, 0, 0, 0}, length: 32}
		idB = ShardID{bits: []byte{0, 0, 0, 0, 0x80}, length: 33}
		checkOrder(t, idA, idB)

		idA = ShardID{bits: []byte{0}, length: 7}
		idA0, idA1 := idA.Split() // from 7 bits to 8 bits
		compareTriple(idA0, idA, idA1)

		idA = idA1
		idA0, idA1 = idA.Split() // from 8 bits to 9 bits
		compareTriple(idA0, idA, idA1)

		idA = ShardID{bits: []byte{0, 0, 0, 0}, length: 31}
		idA0, idA1 = idA.Split() // from 31 bits to 32 bits
		compareTriple(idA0, idA, idA1)
		idA = idA1
		idA0, idA1 = idA.Split() // from 32 bits to 33 bits
		compareTriple(idA0, idA, idA1)
		idA = idA1
		idA0, idA1 = idA.Split() // from 33 bits to 34 bits
		compareTriple(idA0, idA, idA1)

		idA = ShardID{bits: []byte{0xFF, 0xFF, 0xFF, 0xFE}, length: 31}
		idA0, idA1 = idA.Split() // from 31 bits to 32 bits
		compareTriple(idA0, idA, idA1)
		idA = idA0
		idA0, idA1 = idA.Split() // from 32 bits to 33 bits
		compareTriple(idA0, idA, idA1)
	})

	t.Run("sort", func(t *testing.T) {
		all := []ShardID{emptyID, id10, id11, id00, id01, id0, id1}
		slices.SortFunc(all, CompareShardIDs)
		// sorted: [00 0 01 ⌊⌋ 10 1 11]
		expected := []ShardID{id00, id0, id01, emptyID, id10, id1, id11}
		require.Equal(t, expected, all)

		all = []ShardID{id100, id101, id10, id11, id00, id01, id0, id1, emptyID}
		slices.SortFunc(all, CompareShardIDs)
		// sorted: [00 0 01 ⌊⌋ 100 10 101 1 11]
		expected = []ShardID{id00, id0, id01, emptyID, id100, id10, id101, id1, id11}
		require.Equal(t, expected, all, "expected %v, got: %v", expected, all)
	})
}
