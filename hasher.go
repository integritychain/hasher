// Package hasher implements the full SHA2 family of secure hasher256 algorithms from FIPS PUB 180-4.
// It supports a fluent interface for easy and flexible usage, maximal encapsulation for isolation
// and maintainability, multi-step hashing for large or streaming structures, and is compatible with
// dependency injection strategies to simplify testability. Because this package deals with sensitive
// information and problems stem more from "design time" than "run time" errors, the code "fails fast
// and fails hard" upon incorrect usage. There are no dependencies on outside packages. FIPS PUB
// 180-4 may be found at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
package hasher

import (
	"encoding/json"
	"log"
	"reflect"
)

// TODO
// 1. Consider whether Algorithm(), Copy() and InterimSum() should be bound to each type
// 2. Rebuild tests: include max length, interim sum ... everything; measure coverage
// 3. Revise documentation

// Hasher interface
type Hasher interface {
	init(hashAlgorithm HashAlgorithm) Hasher
	Write(message []byte) Hasher
	Sum() interface{}
}

// HashAlgorithm is unique type that will be enumerated
type HashAlgorithm uint32

// Enumerated constant for each hasher256 algorithm
const (
	None       HashAlgorithm = iota
	Sha224     HashAlgorithm = iota
	Sha256     HashAlgorithm = iota
	Sha384     HashAlgorithm = iota
	Sha512     HashAlgorithm = iota
	Sha512t224 HashAlgorithm = iota
	Sha512t256 HashAlgorithm = iota
)

// New constructs a fresh instance. The HashAlgorithm algorithm can be specified here or deferred to init().
func New(hashAlgorithm HashAlgorithm) interface{ Hasher } {

	switch hashAlgorithm {
	case Sha224:
		return new(sha224).init(Sha224)
	case Sha256:
		return new(sha256).init(Sha256)
	case Sha384:
		return new(sha384).init(Sha384)
	case Sha512:
		return new(sha512).init(Sha512)
	case Sha512t224:
		return new(sha512t224).init(Sha512t224)
	case Sha512t256:
		return new(sha512t256).init(Sha512t256)
	default:
		log.Fatal("Unknown (or None) hashAlgorithm")
	}
	return nil
}

func Algorithm(src Hasher) HashAlgorithm {
	switch reflect.TypeOf(src) {
	case reflect.TypeOf(&sha224{}):
		return Sha224
	case reflect.TypeOf(&sha256{}):
		return Sha256
	case reflect.TypeOf(&sha384{}):
		return Sha384
	case reflect.TypeOf(&sha512{}):
		return Sha512
	case reflect.TypeOf(&sha512t224{}):
		return Sha512t224
	case reflect.TypeOf(&sha512t256{}):
		return Sha512t256
	default:
		log.Fatal("Passed bad source Hasher")
	}
	return None
}

func Copy(src Hasher) (Hasher, error) {
	var dst Hasher
	switch Algorithm(src) {
	case Sha224:
		dst = New(Sha224)
	case Sha256:
		dst = New(Sha256)
	case Sha384:
		dst = New(Sha384)
	case Sha512:
		dst = New(Sha512)
	case Sha512t224:
		dst = New(Sha512t224)
	case Sha512t256:
		dst = New(Sha512t256)
	default:
		log.Fatal("Passed bad source Hasher")
	}

	// Marshall source
	originalData, err := json.Marshal(&src)
	if err != nil {
		return nil, err
	}

	// Unmarshall it back into dst
	err = json.Unmarshal(originalData, &dst)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func InterimSum(src Hasher) interface{} {
	var dst Hasher
	dst, err := Copy(src)
	if err != nil {
		log.Fatal("Passed bad source Hasher")
	}
	return dst.Sum()
}
