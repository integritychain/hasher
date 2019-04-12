// Package hasher implements the full SHA2 family of secure hasher256 algorithms from FIPS PUB 180-4.
// It supports a fluent interface for easy and flexible usage, maximal encapsulation for isolation
// and maintainability, multi-step hashing for large or streaming structures, and is compatible with
// dependency injection strategies to simplify testability. Because this package deals with sensitive
// information and problems stem more from "design time" than "run time" errors, the code "fails fast
// and fails hard" upon incorrect usage. There are no dependencies on outside packages. FIPS PUB
// 180-4 may be found at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
package hasher

import (
	"log"
)

// TODO
// 1. Fix then test maxLength logic
// 2. Implement Marshall, Unmarshall
// 3. Clean up code further

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

// Reused magic constants
var maxLengthBytes uint64 = 1 << 63 // Only support up to 2**63 bytes

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
