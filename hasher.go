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
	"fmt"
	"log"
	"reflect"
)

// TODO
// 1. Find out if new can work; find out if shared Init can work; otherwise move on!!
// 2. Fix then test maxLength logic
//X3. Implement Marshall, Unmarshall; What is this json stuff in a struct, codec???
//X4. Implement Thomas' interim calculate function; can we simply copy the hasher and Sum the copy?
// 5. Clean up code further; everything in sha256 should perfectly match sha512
// 6. Fresh look at test strategy; build each small bit, then fuzz everything; also documentation
// 7. Review documentation
// 8. Profiling --> uint64 on sha256!

// Hasher interface
type Hasher interface {
	Init(hashAlgorithm HashAlgorithm) Hasher
	HashAlgorithm() HashAlgorithm
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

// New constructs a fresh instance. The HashAlgorithm algorithm can be specified here or deferred to Init().
func New(hashAlgorithm HashAlgorithm) interface{ Hasher } {

	switch hashAlgorithm {
	case Sha224:
		return new(sha224).Init(Sha224)
	case Sha256:
		return new(sha256).Init(Sha256)
	case Sha384:
		return new(sha384).Init(Sha384)
	case Sha512:
		return new(sha512).Init(Sha512)
	case Sha512t224:
		return new(sha512t224).Init(Sha512t224)
	case Sha512t256:
		return new(sha512t256).Init(Sha512t256)
	default:
		log.Fatal("Unknown (or None) hashAlgorithm")
	}
	return nil
}

func HashAlgorithm2(src Hasher) HashAlgorithm {
	if reflect.TypeOf(src) == reflect.TypeOf(&sha224{}) {
		return Sha224
	}
	switch reflect.TypeOf(src) {
	case reflect.TypeOf(&sha224{}):
		return Sha224
	}
	sType := reflect.TypeOf(src)
	dType := reflect.TypeOf(&sha224{})
	fmt.Printf("%v\n%v", sType, dType)
	return None
}

func Copy(src Hasher) (Hasher, error) {
	var dst Hasher
	switch HashAlgorithm2(src) {
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

	originalData, err := json.Marshal(&src)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(originalData, &dst)
	if err != nil {
		return nil, err
	}
	return dst, nil
}
