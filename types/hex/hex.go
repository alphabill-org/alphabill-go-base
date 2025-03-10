package hex

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

type (
	Uint64 uint64
	Bytes  []byte
)

func (u Uint64) MarshalText() ([]byte, error) {
	return []byte(strconv.FormatUint(uint64(u), 10)), nil
}

func (u *Uint64) UnmarshalText(src []byte) error {
	res, err := strconv.ParseUint(string(src), 10, 64)
	if err == nil {
		*u = Uint64(res)
	}
	return err
}

func (b Bytes) MarshalText() ([]byte, error) {
	return Encode(b), nil
}

func (b *Bytes) UnmarshalText(src []byte) error {
	res, err := Decode(src)
	if err == nil {
		*b = res
	}
	return err
}

func Encode(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src)*2+2)
	copy(dst, `0x`)
	hex.Encode(dst[2:], src)
	return dst
}

func Decode(src []byte) ([]byte, error) {
	src, err := checkHex(src)
	if err != nil {
		return nil, err
	}
	if len(src) == 0 {
		return nil, nil
	}
	dst := make([]byte, len(src)/2)
	_, err = hex.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func checkHex(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X') {
		input = input[2:]
	} else {
		return nil, fmt.Errorf("hex string without 0x prefix")
	}
	if len(input)%2 != 0 {
		return nil, fmt.Errorf("hex string of odd length")
	}
	return input, nil
}
