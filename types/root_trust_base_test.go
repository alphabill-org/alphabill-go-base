package types

import (
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	"github.com/alphabill-org/alphabill-go-base/util"
	"github.com/stretchr/testify/require"
)

func TestNodeInfo_IsValid(t *testing.T) {
	keys := genKeys(1)
	type fields struct {
		NodeID string
		SigKey []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr string
	}{
		{
			name:    "missing node identifier",
			fields:  fields{"", keys["1"].publicKey},
			wantErr: "node identifier is empty",
		},
		{
			name:    "signing key is empty",
			fields:  fields{"1", nil},
			wantErr: "signing key is empty",
		},
		{
			name:    "signing key is invalid",
			fields:  fields{"1", []byte{1, 2}},
			wantErr: "signing key is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &NodeInfo{
				NodeID: tt.fields.NodeID,
				SigKey: tt.fields.SigKey,
			}
			require.ErrorContains(t, x.IsValid(), tt.wantErr)
		})
	}
}

func TestNewTrustBaseGenesis(t *testing.T) {
	keys := genKeys(4)
	type args struct {
		nodes               []*NodeInfo
		unicityTreeRootHash []byte
		opts                []Option
	}
	tests := []struct {
		name       string
		args       args
		verifyFunc func(t *testing.T, tb *RootTrustBaseV1)
		wantErrStr string
	}{
		{
			name:       "empty nodes list",
			args:       args{nodes: nil, unicityTreeRootHash: []byte{1}},
			wantErrStr: "nodes list is empty",
		},
		{
			name: "empty root hash",
			args: args{
				nodes:               []*NodeInfo{NewNodeInfoFromVerifier("1", 1, keys["1"].verifier)},
				unicityTreeRootHash: nil,
			},
			wantErrStr: "unicity tree root hash is empty",
		},
		{
			name: "default settings ok",
			args: args{
				nodes: []*NodeInfo{
					NewNodeInfoFromVerifier("1", 1, keys["1"].verifier),
					NewNodeInfoFromVerifier("2", 1, keys["2"].verifier),
					NewNodeInfoFromVerifier("3", 1, keys["3"].verifier),
				},
				unicityTreeRootHash: []byte{1},
			},
			verifyFunc: func(t *testing.T, tb *RootTrustBaseV1) {
				// verify values
				require.EqualValues(t, 1, tb.Epoch)
				require.EqualValues(t, 1, tb.EpochStartRound)
				require.Len(t, tb.RootNodes, 3)
				require.EqualValues(t, 3, tb.QuorumThreshold)
				require.EqualValues(t, []byte{1}, tb.StateHash)
				require.Nil(t, tb.ChangeRecordHash)
				require.Nil(t, tb.PreviousEntryHash)
				require.Empty(t, tb.Signatures)

				// verify methods
				require.EqualValues(t, 3, tb.GetQuorumThreshold())
				require.EqualValues(t, 0, tb.GetMaxFaultyNodes())
				require.Equal(t, keys["1"].verifier, tb.getRootNode("1").sigVerifier)
				require.Equal(t, keys["2"].verifier, tb.getRootNode("2").sigVerifier)
				require.Equal(t, keys["3"].verifier, tb.getRootNode("3").sigVerifier)
			},
		},
		{
			name: "custom quorum threshold ok (4 of 4 nodes)",
			args: args{
				nodes: []*NodeInfo{
					{
						NodeID: "1",
						SigKey: keys["1"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "2",
						SigKey: keys["2"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "3",
						SigKey: keys["3"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "4",
						SigKey: keys["4"].publicKey,
						Stake:  1,
					},
				},
				unicityTreeRootHash: []byte{1},
				opts:                []Option{WithQuorumThreshold(4)},
			},
			verifyFunc: func(t *testing.T, tb *RootTrustBaseV1) {
				require.EqualValues(t, 4, tb.GetQuorumThreshold())
				require.EqualValues(t, 0, tb.GetMaxFaultyNodes())
			},
		},
		{
			name: "custom quorum threshold too low",
			args: args{
				nodes: []*NodeInfo{
					{
						NodeID: "1",
						SigKey: keys["1"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "2",
						SigKey: keys["2"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "3",
						SigKey: keys["3"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "4",
						SigKey: keys["4"].publicKey,
						Stake:  1,
					},
				},
				unicityTreeRootHash: []byte{1},
				opts:                []Option{WithQuorumThreshold(2)},
			},
			wantErrStr: fmt.Sprintf("quorum threshold must be at least '2/3+1' (min threshold %d got %d)", 3, 2),
		},
		{
			name: "custom quorum threshold too high",
			args: args{
				nodes: []*NodeInfo{
					{
						NodeID: "1",
						SigKey: keys["1"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "2",
						SigKey: keys["2"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "3",
						SigKey: keys["3"].publicKey,
						Stake:  1,
					},
				},
				unicityTreeRootHash: []byte{1},
				opts:                []Option{WithQuorumThreshold(4)},
			},
			wantErrStr: fmt.Sprintf("quorum threshold cannot exceed the total staked amount (max threshold %d got %d)", 3, 4),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tb, err := NewTrustBaseGenesis(tt.args.nodes, tt.args.unicityTreeRootHash, tt.args.opts...)
			if tt.wantErrStr != "" {
				require.ErrorContains(t, err, tt.wantErrStr)
				require.Nil(t, tb)
			} else {
				require.NoError(t, err)
				require.NotNil(t, tb)
			}
			if tt.verifyFunc != nil {
				tt.verifyFunc(t, tb)
			}
		})
	}
}

func TestNewTrustBaseFromFile(t *testing.T) {
	keys := genKeys(3)

	// create trust base from genesis
	tb, err := NewTrustBaseGenesis(
		[]*NodeInfo{NewNodeInfoFromVerifier("1", 1, keys["1"].verifier)},
		[]byte{1},
	)
	require.NoError(t, err)

	// save trust base to file
	trustBaseFile := filepath.Join(t.TempDir(), "root-trust-base.json")
	err = util.WriteJsonFile(trustBaseFile, tb)
	require.NoError(t, err)

	// load trust base from file
	tb, err = NewTrustBaseFromFile(trustBaseFile)
	require.NoError(t, err)

	// verify that verifiers are cached when loading from file
	require.Len(t, tb.GetRootNodes(), 1)
	verifier, err := tb.getRootNode("1").SigVerifier()
	require.NoError(t, err)
	require.Equal(t, keys["1"].verifier, verifier)
}

func TestSignAndVerify(t *testing.T) {
	keys := genKeys(1)
	tb, err := NewTrustBaseGenesis(
		[]*NodeInfo{NewNodeInfoFromVerifier("1", 1, keys["1"].verifier)},
		[]byte{1},
	)
	require.NoError(t, err)

	err = tb.Sign("1", keys["1"].signer)
	require.NoError(t, err)
	require.Len(t, tb.Signatures, 1)
	sig := tb.Signatures["1"]
	require.NotEmpty(t, sig)
	sb, err := tb.SigBytes()
	require.NoError(t, err)
	err = keys["1"].verifier.VerifyBytes(sig, sb)
	require.NoError(t, err)
}

func Test_RootTrustBaseV1_CBOR(t *testing.T) {
	keys := genKeys(3)
	tb, err := NewTrustBaseGenesis(
		[]*NodeInfo{
			NewNodeInfoFromVerifier("1", 1, keys["1"].verifier),
			NewNodeInfoFromVerifier("2", 1, keys["2"].verifier),
			NewNodeInfoFromVerifier("3", 1, keys["3"].verifier),
		},
		[]byte{1},
	)
	require.NoError(t, err)

	t.Run("Marshal - ok", func(t *testing.T) {
		data, err := Cbor.Marshal(tb)
		require.NoError(t, err)

		tb2 := &RootTrustBaseV1{}
		err = Cbor.Unmarshal(data, tb2)
		require.NoError(t, err)

		// call SigVerifier() on all nodes so that caches are equal
		for _, rn := range tb.RootNodes {
			_, err := rn.SigVerifier()
			require.NoError(t, err)
		}

		for _, rn := range tb2.RootNodes {
			_, err := rn.SigVerifier()
			require.NoError(t, err)
		}

		require.EqualValues(t, tb, tb2)
	})

	t.Run("Unmarshal - invalid version", func(t *testing.T) {
		tb.Version = 2
		data, err := Cbor.Marshal(tb)
		require.NoError(t, err)

		tb2 := &RootTrustBaseV1{}
		err = Cbor.Unmarshal(data, tb2)
		require.ErrorContains(t, err, "invalid version (type *types.RootTrustBaseV1), expected 1, got 2")
	})
}

type key struct {
	signer    abcrypto.Signer
	verifier  abcrypto.Verifier
	publicKey []byte
}

func genKeys(count int) map[string]key {
	keys := make(map[string]key, count)
	for i := 1; i <= count; i++ {
		nodeID := strconv.Itoa(i)
		signer, _ := abcrypto.NewInMemorySecp256K1Signer()
		verifier, _ := signer.Verifier()
		publicKey, _ := verifier.MarshalPublicKey()
		keys[nodeID] = key{
			signer:    signer,
			verifier:  verifier,
			publicKey: publicKey,
		}
	}
	return keys
}

func NewTrustBase(t *testing.T, verifiers ...abcrypto.Verifier) RootTrustBase {
	var nodes []*NodeInfo
	for _, v := range verifiers {
		nodes = append(nodes, NewNodeInfoFromVerifier("test", 1, v))
	}
	tb, err := NewTrustBaseGenesis(nodes, []byte{1})
	require.NoError(t, err)
	return tb
}

func NewTrustBaseFromVerifiers(t *testing.T, verifiers map[string]abcrypto.Verifier) RootTrustBase {
	var nodes []*NodeInfo
	for nodeID, v := range verifiers {
		nodes = append(nodes, NewNodeInfoFromVerifier(nodeID, 1, v))
	}
	tb, err := NewTrustBaseGenesis(nodes, []byte{1})
	require.NoError(t, err)
	return tb
}
