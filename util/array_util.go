package util

import (
	"math/rand"
)

func ShuffleSliceCopy[T any](src []T) []T {
	dst := make([]T, len(src))
	copy(dst, src)
	rand.Shuffle(len(dst), func(i, j int) { dst[i], dst[j] = dst[j], dst[i] })
	return dst
}

/*
TransformSlice processes input slice s by calling the mapper callback for each
element and returning the slice of values returned by the callback.

Could be used for extracting single field values from slice of structs etc.
*/
func TransformSlice[S ~[]E, E any, V any](s S, mapper func(E) V) []V {
	r := make([]V, len(s))
	for i, v := range s {
		r[i] = mapper(v)
	}
	return r
}
