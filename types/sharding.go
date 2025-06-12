package types

import (
	"bytes"
	"fmt"
	"iter"
	"math/bits"
	"slices"

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

func (id ShardID) String() (s string) {
	byteCnt := id.length / 8
	for i := uint(0); i < byteCnt; i++ {
		s += fmt.Sprintf("%08b", id.bits[i])
	}
	if b := id.length % 8; b > 0 {
		s += fmt.Sprintf("%08b", id.bits[byteCnt])[:b]
	}
	return s
}

/*
Clone creates copy of the ID.
*/
func (id ShardID) Clone() ShardID {
	return ShardID{bits: bytes.Clone(id.bits), length: id.length}
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
	return Cbor.Marshal(id.Bytes())
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

/*
First return value is 32 bits from the ID starting at the byte "i". If there is less
than 32 bits of the ID left then the least significant bits are zero filled.
Second return value is a mask to the bit which is the first bit after the ID bits (if
the ID has more than 31 bits left then mask==0).
*/
func (id *ShardID) bits32(i uint) (uint32, uint32) {
	r := id.length - min(id.length, i*8)
	mask := uint32(0x80000000) >> r
	switch {
	case r == 0:
		return 0, mask
	case r <= 8:
		return uint32(id.bits[i]) << 24, mask
	case r <= 16:
		_ = id.bits[i+1]
		return uint32(id.bits[i])<<24 | uint32(id.bits[i+1])<<16, mask
	case r <= 24:
		_ = id.bits[i+2]
		return uint32(id.bits[i])<<24 | uint32(id.bits[i+1])<<16 | uint32(id.bits[i+2])<<8, mask
	default:
		_ = id.bits[i+3]
		return uint32(id.bits[i])<<24 | uint32(id.bits[i+1])<<16 | uint32(id.bits[i+2])<<8 | uint32(id.bits[i+3]), mask
	}
}

/*
CompareShardIDs compares ShardIDs, it's suitable to be used as "cmp" argument
of slices.SortFunc, ie it returns
  - a negative number when a < b
  - a positive number when a > b
  - zero when a == b or a and b are incomparable in the sense of a strict weak ordering.

It sorts the IDs in the topological order: c∥0∥x ≺ c ≺ c∥1∥y for all c, x, y in {0, 1}∗.
For example, the subset {0,1}≤2 is ordered as follows: {00 ≺ 0 ≺ 01 ≺ ⌊⌋ ≺ 10 ≺ 1 ≺ 11}.
*/
func CompareShardIDs(a, b ShardID) int {
	for i := uint(0); ; i += 4 {
		bitsA, am := a.bits32(i)
		bitsB, bm := b.bits32(i)
		if diff := bitsA ^ bitsB; am|bm|diff != 0 {
			mask := max(am, bm)
			if diff > mask {
				mask = 0x80000000 >> bits.LeadingZeros32(diff)
			}
			switch {
			case a.length > b.length:
				if bitsA&mask == 0 {
					return -1
				}
				return 1
			case a.length < b.length:
				if bitsB&mask == 0 {
					return 1
				}
				return -1
			default:
				return int(bitsA) - int(bitsB)
			}
		}
	}
}

/*
NewShardingScheme creates sharding scheme based on list of shard IDs.
Returns error when the resulting scheme is not valid.
*/
func NewShardingScheme(ids []ShardID) (ShardingScheme, error) {
	ss := buildShardingScheme(ids)
	return ss, ss.IsValid()
}

/*
Zero value is a valid sharding scheme with single shard (with empty shard ID).
*/
type ShardingScheme struct {
	next0 *ShardingScheme
	next1 *ShardingScheme
	id    ShardID
}

/*
Split splits the given shard and returns the IDs of the two new shards.
Only leafs of the shard tree can be split.
*/
func (ss *ShardingScheme) Split(id ShardID) (ShardID, ShardID, error) {
	node, err := ss.findNode(id)
	if err != nil {
		return ShardID{}, ShardID{}, err
	}

	if node.next0 != nil || node.next1 != nil {
		return ShardID{}, ShardID{}, fmt.Errorf("shard ID %s is not a leaf", id)
	}

	id0, id1 := node.id.Split()
	node.next0 = &ShardingScheme{id: id0}
	node.next1 = &ShardingScheme{id: id1}
	return id0, id1, nil
}

/*
Merge removes child nodes of the given ID so that the ID becomes leaf in the shard tree.
Both child IDs must be leafs themselves.
*/
func (ss *ShardingScheme) Merge(id ShardID) error {
	node, err := ss.findNode(id)
	if err != nil {
		return err
	}
	if node.next0 == nil || node.next1 == nil {
		return fmt.Errorf("node %s is a leaf", id)
	}
	if node.next0.next0 != nil || node.next0.next1 != nil {
		return fmt.Errorf("child 0 of the %s is not a leaf", id)
	}
	if node.next1.next0 != nil || node.next1.next1 != nil {
		return fmt.Errorf("child 1 of the %s is not a leaf", id)
	}

	node.next0 = nil
	node.next1 = nil
	return nil
}

func (ss *ShardingScheme) findNode(id ShardID) (*ShardingScheme, error) {
	node := ss
	mask := byte(0)
	value := byte(0)
	byteIdx := 0
	for range id.length {
		if mask == 0 {
			mask = 0x80
			value = id.bits[byteIdx]
			byteIdx++
		}
		if value&mask == 0 {
			node = node.next0
		} else {
			node = node.next1
		}
		if node == nil {
			return nil, fmt.Errorf("shard ID %s is not in the scheme", id)
		}
		mask >>= 1
	}
	return node, nil
}

/*
Shard returns the shard ID of the unit ID according to the sharding scheme.

We assume that the UnitID is already validated against PDR, ie it's length
is greater or equal to the longest (allowed) ShardID in the ShardingScheme!
*/
func (ss ShardingScheme) Shard(id UnitID) ShardID {
	node := &ss
	mask := byte(0x80)
	value := id[0]
	byteIdx := 0
	for cn := node; cn != nil; mask >>= 1 {
		if mask == 0 {
			mask = 0x80
			byteIdx++
			value = id[byteIdx]
		}
		node = cn
		if value&mask == 0 {
			cn = cn.next0
		} else {
			cn = cn.next1
		}
	}
	return node.id
}

/*
All returns all shard IDs in the scheme.
*/
func (ss ShardingScheme) All() iter.Seq[ShardID] {
	return func(yield func(ShardID) bool) {
		stack := []*ShardingScheme{&ss}
		for cnt := len(stack); cnt > 0; {
			cnt--
			cn := stack[cnt]
			stack = stack[:cnt]
			if cn.next0 == nil && cn.next1 == nil {
				if !yield(cn.id) {
					return
				}
			} else {
				stack = append(stack, cn.next1, cn.next0)
				cnt += 2
			}
		}
	}
}

func (ss ShardingScheme) IsValid() error {
	return ss.isValid(0, 0)
}

/*
- bitCount - the length of the shard ID
- bit - the expected value of the last bit (at index bitCount-1)
*/
func (ss ShardingScheme) isValid(bit byte, bitCount uint) error {
	if ss.id.length != bitCount {
		return fmt.Errorf("expected shard ID length to be %d bits, got %d (%s)", bitCount, ss.id.length, ss.id)
	}
	if bitCount > 0 {
		bitIdx := bitCount - 1
		B, b := bitIdx/8, bitIdx%8
		if v := (ss.id.bits[B] >> (7 - b)) & 1; v != bit {
			return fmt.Errorf("expected bit %d to be %d, got %d (%s)", bitIdx, bit, v, ss.id)
		}
	}

	if ss.next0 == nil && ss.next1 == nil {
		return nil
	}
	if ss.next0 == nil {
		return fmt.Errorf("shard ID %q has no sibling", ss.next1.id)
	}
	if ss.next1 == nil {
		return fmt.Errorf("shard ID %q has no sibling", ss.next0.id)
	}

	if err := ss.next0.isValid(0, bitCount+1); err != nil {
		return err
	}
	if err := ss.next1.isValid(1, bitCount+1); err != nil {
		return err
	}
	return nil
}

func (ss ShardingScheme) MarshalCBOR() ([]byte, error) {
	ids := slices.Collect(ss.All())
	slices.SortFunc(ids, CompareShardIDs)
	return Cbor.Marshal(ids)
}

func (ss *ShardingScheme) UnmarshalCBOR(data []byte) (err error) {
	ids := []ShardID{}
	if err := Cbor.Unmarshal(data, &ids); err != nil {
		return fmt.Errorf("decoding shard ID list: %w", err)
	}
	scheme := buildShardingScheme(ids)
	if err := scheme.IsValid(); err != nil {
		return fmt.Errorf("invalid scheme: %w", err)
	}
	*ss = scheme
	return nil
}

/*
build sharding scheme out of ID-s.
NB! Resulting scheme might be invalid (ie not prefix free)!
*/
func buildShardingScheme(ids []ShardID) ShardingScheme {
	ss := ShardingScheme{}
	for _, id := range ids {
		cn := &ss
		mask := byte(0)
		value := byte(0)
		byteIdx := 0
		for range id.length {
			if mask == 0 {
				mask = 0b1000_0000
				value = id.bits[byteIdx]
				byteIdx++
			}
			if value&mask == 0 {
				if cn.next0 == nil {
					id0, _ := cn.id.Split()
					cn.next0 = &ShardingScheme{id: id0}
				}
				cn = cn.next0
			} else {
				if cn.next1 == nil {
					_, id1 := cn.id.Split()
					cn.next1 = &ShardingScheme{id: id1}
				}
				cn = cn.next1
			}
			mask >>= 1
		}
	}
	return ss
}
