// Package hasher provides the full SHA2 family of secure hash algorithms from FIPS PUB 180-4.
// It supports a fluent interface for easy and flexible usage, maximal encapsulation for isolation
// and maintainability, interim sums for protocols requiring intermediate results, and multi-step
// hashing for large and/or streaming applications. Because this package deals with potentially
// sensitive information and problems typically stem more from "design time" than "run time" errors,
// the code "fails fast and fails hard" upon incorrect usage. There are no dependencies on packages
// outside of the standard library. FIPS PUB 180-4 may be found at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
package hasher

import (
	"encoding/json"
	"log"
)

// TODO:    Create discussion.adoc document
// Argghhh: GoDoc does not detected exported methods of un-exported structs? #528
//          https://github.com/golang/gddo/issues/528

// Hasher interface
type Hasher interface {
	Copy() Hasher
	HashAlgorithm() HashAlgorithm
	InterimSum() interface{}
	Sum() interface{}
	Write(message []byte) Hasher
}

// HashAlgorithm is a unique type that will be enumerated
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

// LogFatal can be overridden to prevent fatal exits (e.g. for testing)
var LogFatal = log.Fatal

// New constructs a fresh instance of the specified HashAlgorithm
func New(hashAlgorithm HashAlgorithm) Hasher {
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
	case None:
		LogFatal("HashAlgorithm \"None\" specified")
	default:
		LogFatal("Unknown hashAlgorithm")
	}
	return nil
}

// hasherCopy deep copy via marshall the src then unmarshall into dst (independent of HashAlgorithm)
func hasherCopy(dst Hasher, src Hasher) Hasher {
	originalData, err := json.Marshal(&src)
	if err != nil {
		LogFatal("hasherCopy() unable to serialize source")
	}
	err = json.Unmarshal(originalData, &dst)
	if err != nil {
		LogFatal("hasherCopy() unable to deserialize destimation")
	}
	return dst
}
