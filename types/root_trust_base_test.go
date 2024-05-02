package types

import (
	"path/filepath"
	"strconv"
	"testing"

	abcrypto "github.com/alphabill-org/alphabill-go-base/crypto"
	"github.com/alphabill-org/alphabill-go-base/util"
	"github.com/stretchr/testify/require"
)

func TestNewTrustBaseGenesis(t *testing.T) {
	keys := genKeys(3)
	type args struct {
		nodes               []*NodeInfo
		unicityTreeRootHash []byte
		opts                []Option
	}
	tests := []struct {
		name       string
		args       args
		verifyFunc func(t *testing.T, tb *RootTrustBaseV0)
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
				nodes:               []*NodeInfo{NewNodeInfo("1", 1, keys["1"].verifier)},
				unicityTreeRootHash: nil,
			},
			wantErrStr: "unicity tree root hash is empty",
		},
		{
			name: "default settings ok",
			args: args{
				nodes: []*NodeInfo{
					NewNodeInfo("1", 1, keys["1"].verifier),
					NewNodeInfo("2", 1, keys["2"].verifier),
					NewNodeInfo("3", 1, keys["3"].verifier),
				},
				unicityTreeRootHash: []byte{1},
			},
			verifyFunc: func(t *testing.T, tb *RootTrustBaseV0) {
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
				verifiers, err := tb.GetVerifiers()
				require.NoError(t, err)
				require.Equal(t, keys["1"].verifier, verifiers["1"])
				require.Equal(t, keys["2"].verifier, verifiers["2"])
				require.Equal(t, keys["3"].verifier, verifiers["3"])
			},
		},
		{
			name: "custom quorum threshold ok",
			args: args{
				nodes: []*NodeInfo{
					{
						NodeID:    "1",
						PublicKey: keys["1"].publicKey,
						Stake:     1,
					},
					{
						NodeID:    "2",
						PublicKey: keys["2"].publicKey,
						Stake:     1,
					},
					{
						NodeID:    "3",
						PublicKey: keys["3"].publicKey,
						Stake:     1,
					},
				},
				unicityTreeRootHash: []byte{1},
				opts:                []Option{WithQuorumThreshold(2)},
			},
			verifyFunc: func(t *testing.T, tb *RootTrustBaseV0) {
				require.EqualValues(t, 2, tb.GetQuorumThreshold())
				require.EqualValues(t, 1, tb.GetMaxFaultyNodes())
			},
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
		[]*NodeInfo{NewNodeInfo("1", 1, keys["1"].verifier)},
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
	verifiers, err := tb.GetVerifiers()
	require.NoError(t, err)
	require.Len(t, verifiers, 1)
	require.Equal(t, keys["1"].verifier, verifiers["1"])
}

func TestSignAndVerify(t *testing.T) {
	keys := genKeys(1)
	tb, err := NewTrustBaseGenesis(
		[]*NodeInfo{NewNodeInfo("1", 1, keys["1"].verifier)},
		[]byte{1},
	)
	require.NoError(t, err)

	err = tb.Sign("1", keys["1"].signer)
	require.NoError(t, err)
	require.Len(t, tb.Signatures, 1)
	sig := tb.Signatures["1"]
	require.NotEmpty(t, sig)
	err = keys["1"].verifier.VerifyBytes(sig, tb.SigBytes())
	require.NoError(t, err)
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
		nodes = append(nodes, NewNodeInfo("test", 1, v))
	}
	tb, err := NewTrustBaseGenesis(nodes, []byte{1})
	require.NoError(t, err)
	return tb
}

func NewTrustBaseFromVerifiers(t *testing.T, verifiers map[string]abcrypto.Verifier) RootTrustBase {
	var nodes []*NodeInfo
	for nodeID, v := range verifiers {
		nodes = append(nodes, NewNodeInfo(nodeID, 1, v))
	}
	tb, err := NewTrustBaseGenesis(nodes, []byte{1})
	require.NoError(t, err)
	return tb
}
