package types

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	test "github.com/alphabill-org/alphabill-go-base/testutils"
)

func Test_CreateShardTree(t *testing.T) {
	t.Run("empty states input", func(t *testing.T) {
		// empty scheme expects input for empty shard id
		scheme := ShardingScheme{}
		tree, err := CreateShardTree(scheme, nil, crypto.SHA256)
		require.EqualError(t, err, `missing input for shard ""`)
		require.Empty(t, tree)

		tree, err = CreateShardTree(scheme, []ShardTreeInput{}, crypto.SHA256)
		require.EqualError(t, err, `missing input for shard ""`)
		require.Empty(t, tree)

		// non-empty scheme
		scheme = ShardingScheme{}
		_, _, err = scheme.Split(ShardID{})
		require.NoError(t, err)
		tree, err = CreateShardTree(scheme, []ShardTreeInput{}, crypto.SHA256)
		require.EqualError(t, err, `missing input for shard "0"`)
		require.Empty(t, tree)
	})

	t.Run("shard count != input count", func(t *testing.T) {
		// empty scheme (== 1 shard with empty ID) but two inputs
		scheme := ShardingScheme{}
		in := []ShardTreeInput{
			{Shard: ShardID{}, IR: &InputRecord{}},
			{Shard: ShardID{}, IR: &InputRecord{}},
		}
		tree, err := CreateShardTree(scheme, in, crypto.SHA256)
		require.EqualError(t, err, `scheme has 1 shards but got input with 2 items`)
		require.Empty(t, tree)

		// empty scheme but we send input for non-empty shard IDs
		id0, id1 := ShardID{}.Split()
		in = []ShardTreeInput{
			{Shard: id0, IR: &InputRecord{}},
			{Shard: id1, IR: &InputRecord{}},
		}
		tree, err = CreateShardTree(scheme, in, crypto.SHA256)
		require.EqualError(t, err, `missing input for shard ""`)
		require.Empty(t, tree)

		// scheme{0, 1} but input for "0" only
		scheme = ShardingScheme{}
		_, _, err = scheme.Split(ShardID{})
		require.NoError(t, err)
		in = []ShardTreeInput{{Shard: id0, IR: &InputRecord{}}}
		tree, err = CreateShardTree(scheme, in, crypto.SHA256)
		require.EqualError(t, err, `missing input for shard "1"`)
		require.Empty(t, tree)

		// extra input with empty id (not valid for the scheme{0, 1})
		in = []ShardTreeInput{
			{Shard: ShardID{}, IR: &InputRecord{}},
			{Shard: id0, IR: &InputRecord{}},
			{Shard: id1, IR: &InputRecord{}},
		}
		tree, err = CreateShardTree(scheme, in, crypto.SHA256)
		require.EqualError(t, err, `scheme has 2 shards but got input with 3 items`)
		require.Empty(t, tree)
	})

	t.Run("invalid scheme", func(t *testing.T) {
		scheme := ShardingScheme{}
		id0, _, err := scheme.Split(ShardID{})
		require.NoError(t, err)
		in := generateSTInput(scheme)
		scheme = buildShardingScheme([]ShardID{id0})
		tree, err := CreateShardTree(scheme, in, crypto.SHA256)
		require.EqualError(t, err, `invalid sharding scheme: shard ID "0" has no sibling`)
		require.Empty(t, tree)
	})

	t.Run("valid", func(t *testing.T) {
		// empty scheme (== 1 shard)
		scheme := ShardingScheme{}
		in := []ShardTreeInput{{Shard: ShardID{}, IR: &InputRecord{}}}
		tree, err := CreateShardTree(scheme, in, crypto.SHA256)
		require.NoError(t, err)
		require.Len(t, tree, 1)

		//shards "0" and "1"
		scheme = ShardingScheme{}
		_, _, err = scheme.Split(ShardID{})
		require.NoError(t, err)
		in = generateSTInput(scheme)
		tree, err = CreateShardTree(scheme, in, crypto.SHA256)
		require.NoError(t, err)
		require.Len(t, tree, 3) // we also have item for empty ID (aka RootHash)
	})
}

func Test_ShardTree_SiblingHashes(t *testing.T) {
	t.Run("single shard scheme", func(t *testing.T) {
		id := ShardID{}
		in := generateSTInput(ShardingScheme{})
		tree, err := CreateShardTree(ShardingScheme{}, in, crypto.SHA256)
		require.NoError(t, err)
		require.Empty(t, tree.siblingHashes(id))
		require.NotEmpty(t, tree.RootHash())
	})

	t.Run("multi shard scheme", func(t *testing.T) {
		// build scheme
		id0, id1 := ShardID{}.Split() // "0", "1"
		id00, id01 := id0.Split()     // "00", "01"
		id10, id11 := id1.Split()     // "10", "11"
		scheme, err := NewShardingScheme([]ShardID{id00, id01, id10, id11})
		require.NoError(t, err)
		// what we expect sibling IDs of the given shard to be
		siblingID := map[string][]ShardID{
			id0.Key():  {id1},       // 0 -> 1
			id1.Key():  {id0},       // 1 -> 0
			id00.Key(): {id01, id1}, // 00 -> 01, 1
			id01.Key(): {id00, id1}, // 01 -> 00, 1
			id10.Key(): {id11, id0}, // 10 -> 11, 0
			id11.Key(): {id10, id0}, // 11 -> 10, 0
		}

		tree, err := CreateShardTree(scheme, generateSTInput(scheme), crypto.SHA256)
		require.NoError(t, err)

		for id := range scheme.All() {
			sibH := tree.siblingHashes(id)
			sibIDs := siblingID[id.Key()]
			for i, sid := range sibIDs {
				require.Equal(t, sibH[i], tree[sid.Key()], "shard %s sibling[%d] = %s", id, i, sid)
			}
		}
	})
}

func Test_ShardTreeCertificate_ComputeCertificate(t *testing.T) {

	findSTInput := func(t *testing.T, data []ShardTreeInput, shard ShardID) ShardTreeInput {
		t.Helper()
		for _, v := range data {
			if shard.Equal(v.Shard) {
				return v
			}
		}
		t.Fatalf("no data for shard %s", shard)
		return ShardTreeInput{}
	}

	t.Run("single shard scheme", func(t *testing.T) {
		scheme := ShardingScheme{}
		in := []ShardTreeInput{{Shard: ShardID{}, IR: &InputRecord{}, TRHash: []byte{7, 7, 7}, ShardConfHash: []byte{8, 8, 8}}}
		tree, err := CreateShardTree(scheme, in, crypto.SHA256)
		require.NoError(t, err)
		require.Len(t, tree, 1)

		cert, err := tree.Certificate(ShardID{})
		require.NoError(t, err)
		require.NoError(t, cert.IsValid())
		rh, err := cert.ComputeCertificateHash(in[0].IR, in[0].TRHash, in[0].ShardConfHash, crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, tree.RootHash(), rh)
	})

	t.Run("multi shard scheme", func(t *testing.T) {
		// build scheme
		id0, id1 := ShardID{}.Split() // "0", "1"
		id00, id01 := id0.Split()     // "00", "01"
		id010, id011 := id01.Split()  // "010", "011"
		scheme, err := NewShardingScheme([]ShardID{id010, id011, id00, id1})
		require.NoError(t, err)

		in := generateSTInput(scheme)
		tree, err := CreateShardTree(scheme, in, crypto.SHA256)
		require.NoError(t, err)

		for id := range scheme.All() {
			cert, err := tree.Certificate(id)
			require.NoError(t, err)
			data := findSTInput(t, in, id)
			require.NoError(t, cert.IsValid())
			rh, err := cert.ComputeCertificateHash(data.IR, data.TRHash, data.ShardConfHash, crypto.SHA256)
			require.NoError(t, err)
			require.Equal(t, tree.RootHash(), rh, "shard %s cert %v", id, cert)
		}
	})
}

func Test_ShardTreeCertificate_Certificate(t *testing.T) {
	t.Run("invalid input", func(t *testing.T) {
		// empty scheme
		scheme := ShardingScheme{}
		in := []ShardTreeInput{{Shard: ShardID{}, IR: &InputRecord{}, TRHash: []byte{7, 7, 7}}}
		tree, err := CreateShardTree(scheme, in, crypto.SHA256)
		require.NoError(t, err)

		id0, id1 := ShardID{}.Split() // "0", "1"
		cert, err := tree.Certificate(id0)
		require.EqualError(t, err, `shard "0" is not in the tree`)
		require.Empty(t, cert)

		// non-empty scheme
		scheme = buildShardingScheme([]ShardID{id0, id1})
		in = generateSTInput(scheme)
		tree, err = CreateShardTree(scheme, in, crypto.SHA256)
		require.NoError(t, err)

		cert, err = tree.Certificate(ShardID{bits: []byte{128}, length: 3})
		require.EqualError(t, err, `shard "100" is not in the tree`)
		require.Empty(t, cert)
	})
}

// generate input records with enough randomness that we have different hashes
func generateSTInput(scheme ShardingScheme) []ShardTreeInput {
	out := []ShardTreeInput{}
	for shard := range scheme.All() {
		out = append(out,
			ShardTreeInput{
				Shard:         shard,
				IR:            &InputRecord{Hash: test.RandomBytes(8), SumOfEarnedFees: uint64(shard.Length())},
				TRHash:        test.RandomBytes(8),
				ShardConfHash: test.RandomBytes(8),
			},
		)
	}
	return out
}
