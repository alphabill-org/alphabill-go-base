package types

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"slices"

	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types/hex"
)

type ShardID struct {
	bits []byte
	// length is shard ID length in bits.
	length uint
}

// Length returns shard ID length in bits.
func (id ShardID) Length() uint { return id.length }

// Bytes returns binary serialization of the shard ID suitable for hashing
func (id ShardID) Bytes() []byte {
	return encodeBitstring(id.bits, id.length)
}

/*
Key is intended to be used where comparable shard ID is needed (ie map key).
*/
func (id ShardID) Key() string {
	return string(id.Bytes())
}

func (id ShardID) AddToHasher(h abhash.Hasher) {
	h.Write(id.Bytes())
}

func (id ShardID) String() (s string) {
	byteCnt := id.length / 8
	for i := 0; i < int(byteCnt); i++ {
		s += fmt.Sprintf("%08b", id.bits[i])
	}
	if b := id.length % 8; b > 0 {
		s += fmt.Sprintf("%08b", id.bits[byteCnt])[:b]
	}
	return s
}

/*
Split increases shard ID length by one bit and returns the two new IDs.
The original shard ID is not altered.
*/
func (id ShardID) Split() (ShardID, ShardID) {
	bitCnt := id.length + 1
	if id.length%8 == 0 {
		return ShardID{bits: append(slices.Clone(id.bits), 0), length: bitCnt},
			ShardID{bits: append(slices.Clone(id.bits), 128), length: bitCnt}
	}

	b1 := slices.Clone(id.bits)
	b1[len(b1)-1] |= 1 << (7 - id.length%8)
	return ShardID{bits: slices.Clone(id.bits), length: bitCnt},
		ShardID{bits: b1, length: bitCnt}
}

func (id ShardID) Equal(v ShardID) bool {
	return id.length == v.length && bytes.Equal(id.bits, v.bits)
}

/*
Comparator returns function which checks does the byte slice argument
have the prefix which matches the shard ID.
NB! It is callers responsibility to not pass shorter slice than the shard id!
*/
func (id ShardID) Comparator() func([]byte) bool {
	switch {
	case id.length == 0:
		return func(b []byte) bool { return true }
	case id.length <= 8:
		mask := byte(0xFF << (8 - id.length))
		return func(b []byte) bool { return b[0]&mask == id.bits[0] }
	case id.length <= 16:
		sid := uint16(id.bits[0])<<8 | uint16(id.bits[1])
		mask := uint16(0xFFFF << (16 - id.length))
		return func(b []byte) bool {
			_ = b[1]
			v := uint16(b[0])<<8 | uint16(b[1])
			return v&mask == sid
		}
	default:
		byteCnt, bitCnt := id.length/8, id.length%8
		mask := byte(0xFF << (8 - bitCnt))
		return func(b []byte) bool {
			return bytes.HasPrefix(b, id.bits[:byteCnt]) && (bitCnt == 0 || b[byteCnt]&mask == id.bits[byteCnt])
		}
	}
}

func (id ShardID) MarshalText() ([]byte, error) {
	return hex.Encode(encodeBitstring(id.bits, id.length)), nil
}

func (id *ShardID) UnmarshalText(src []byte) error {
	res, err := hex.Decode(src)
	if err != nil {
		return fmt.Errorf("decoding from hex: %w", err)
	}
	if id.bits, id.length, err = decodeBitstring(res); err != nil {
		return fmt.Errorf("decoding bitstring: %w", err)
	}
	// some tests use "deep equal" comparison and it will break if we
	// use empty slice instead of nil (as the ShardID zero value does, but
	// decodeBitstring returns empty non nil slice for zero length bit string)
	if id.length == 0 && id.bits != nil {
		id.bits = nil
	}
	return nil
}

func (id ShardID) MarshalCBOR() ([]byte, error) {
	return Cbor.Marshal(encodeBitstring(id.bits, id.length))
}

func (id *ShardID) UnmarshalCBOR(data []byte) (err error) {
	var b []byte
	if err := Cbor.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("decoding bitstring bytes from CBOR: %w", err)
	}
	if id.bits, id.length, err = decodeBitstring(b); err != nil {
		return fmt.Errorf("decoding bitstring: %w", err)
	}
	// some tests use "deep equal" comparison and it will break if we
	// use empty slice instead of nil (as the ShardID zero value does, but
	// decodeBitstring returns empty non nil slice for zero length bit string)
	if id.length == 0 && id.bits != nil {
		id.bits = nil
	}
	return nil
}

type ShardingScheme []ShardID

func (sh ShardingScheme) AddToHasher(h abhash.Hasher) {
	h.Write(len(sh))

	// todo: id-s must be sorted? lexically or topologically?
	// or do we assume that the list is kept sorted?
	for _, v := range sh {
		v.AddToHasher(h)
	}
}

/*
All returns iterator over all shard IDs in the sharding scheme.

For a single shard scheme (empty list) single empty shard ID is returned.
*/
func (sh ShardingScheme) All() iter.Seq[ShardID] {
	if len(sh) == 0 {
		return func(yield func(ShardID) bool) { yield(ShardID{}) }
	}

	return func(yield func(ShardID) bool) {
		for _, id := range sh {
			if !yield(id) {
				return
			}
		}
	}
}

func (sh ShardingScheme) IsValid() error {
	// single shard scheme is denoted by empty slice, there is no valid case with single item
	if len(sh) == 1 {
		return fmt.Errorf("scheme can't contain single shard, got %q", sh[0])
	}

	for idxA, idA := range sh {
		if idA.length == 0 {
			return errors.New("scheme may not contain empty shard ID")
		}
		isPrefixOf := idA.Comparator()
		for idxB, idB := range sh {
			if idA.length <= idB.length && idxA != idxB {
				if isPrefixOf(idB.bits) {
					return fmt.Errorf("scheme is not prefix-free: %s is prefix of %s", idA, idB)
				}
			}
		}
	}

	return nil
}
