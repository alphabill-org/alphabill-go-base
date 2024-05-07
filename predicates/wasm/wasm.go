package wasm

import (
	"errors"
)

const PredicateEngineID = 1

/*
PredicateParams is the data struct encoded in Predicate.Params field for WASM predicates
*/
type PredicateParams struct {
	_          struct{} `cbor:",toarray"`
	Entrypoint string   // function name to call from the WASM binary
	Args       []byte   // "fixed arguments" i.e. configuration for the WASM predicate
}

func (pp PredicateParams) IsValid() error {
	if pp.Entrypoint == "" {
		return errors.New("predicate function name (entrypoint) must be assigned")
	}

	// do not restrict Args length here - this struct is only usable as part of
	// Predicate struct and we enforce maximum predicate size there?

	return nil
}
