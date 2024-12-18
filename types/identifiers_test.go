package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_BytesToPartitionID(t *testing.T) {
	t.Run("invalid input", func(t *testing.T) {
		id, err := BytesToPartitionID(nil)
		require.Zero(t, id)
		require.EqualError(t, err, `partition ID length must be 4 bytes, got 0 bytes`)

		id, err = BytesToPartitionID([]byte{})
		require.Zero(t, id)
		require.EqualError(t, err, `partition ID length must be 4 bytes, got 0 bytes`)

		id, err = BytesToPartitionID([]byte{1})
		require.Zero(t, id)
		require.EqualError(t, err, `partition ID length must be 4 bytes, got 1 bytes`)

		id, err = BytesToPartitionID([]byte{2, 1})
		require.Zero(t, id)
		require.EqualError(t, err, `partition ID length must be 4 bytes, got 2 bytes`)

		id, err = BytesToPartitionID([]byte{3, 2, 1})
		require.Zero(t, id)
		require.EqualError(t, err, `partition ID length must be 4 bytes, got 3 bytes`)

		id, err = BytesToPartitionID([]byte{5, 4, 3, 2, 1})
		require.Zero(t, id)
		require.EqualError(t, err, `partition ID length must be 4 bytes, got 5 bytes`)

		id, err = BytesToPartitionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})
		require.Zero(t, id)
		require.EqualError(t, err, `partition ID length must be 4 bytes, got 8 bytes`)
	})

	t.Run("valid input", func(t *testing.T) {
		// testing that we get expected integer from bytes (so basically endianess check?)
		id, err := BytesToPartitionID([]byte{0, 0, 0, 0})
		require.NoError(t, err)
		require.EqualValues(t, 0, id)

		id, err = BytesToPartitionID([]byte{0, 0, 0, 1})
		require.NoError(t, err)
		require.EqualValues(t, 1, id)

		id, err = BytesToPartitionID([]byte{0, 0, 1, 0})
		require.NoError(t, err)
		require.EqualValues(t, 0x0100, id)

		id, err = BytesToPartitionID([]byte{0, 1, 0, 0})
		require.NoError(t, err)
		require.EqualValues(t, 0x010000, id)

		id, err = BytesToPartitionID([]byte{1, 0, 0, 0})
		require.NoError(t, err)
		require.EqualValues(t, 0x01000000, id)
	})
}

func Test_PartitionID_conversion(t *testing.T) {
	t.Run("converting bytes to ID and back", func(t *testing.T) {
		var cases = [][]byte{{0, 0, 0, 0}, {0, 0, 0, 1}, {0, 0, 2, 0}, {0, 3, 0, 0}, {4, 0, 0, 0}, {1, 2, 3, 4}, {0x10, 0xA0, 0xB0, 0xC0}}
		for _, tc := range cases {
			id, err := BytesToPartitionID(tc)
			if err != nil {
				t.Errorf("converting bytes %X to ID: %v", tc, err)
				continue
			}
			if b := id.Bytes(); !bytes.Equal(b, tc) {
				t.Errorf("expected ID %s as bytes %X, got %X", id, tc, b)
			}
		}
	})

	t.Run("converting ID to bytes and back", func(t *testing.T) {
		var cases = []PartitionID{0, 0x01, 0x0200, 0x030000, 0x04000000, 0xFF, 0xFF12, 0xFEDCBA98}
		for _, tc := range cases {
			b := tc.Bytes()
			id, err := BytesToPartitionID(b)
			if err != nil {
				t.Errorf("converting %s (bytes %X) back to ID: %v", tc, b, err)
				continue
			}
			if id != tc {
				t.Errorf("expected %s got %s from bytes %X", tc, id, b)
			}
		}
	})
}

func Test_PartitionID_String(t *testing.T) {
	var id PartitionID // zero value
	require.Equal(t, "00000000", id.String())

	id = 0x00000001
	require.Equal(t, "00000001", id.String())

	id = 0xFF000010
	require.Equal(t, "FF000010", id.String())

	id = 0xFE01209A
	require.Equal(t, "FE01209A", id.String())
}
