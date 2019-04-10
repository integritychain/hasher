// Package hasher implements the full SHA2 family of secure hash algorithms from FIPS PUB 180-4.
// It supports a fluent interface for easy and flexible usage, maximal encapsulation for isolation
// and maintainability, multi-step hashing for large or streaming structures, and is compatible with
// dependency injection strategies to simplify testability. Because this package deals with sensitive
// information and problems stem more from "design time" than "run time" errors, the code "fails fast
// and fails hard" upon incorrect usage. There are no dependencies on outside packages. FIPS PUB
// 180-4 may be found at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
package hasher

import (
	"encoding/binary"
	"log"
	"math/bits"
)

// TODO
// 1. Fix then test maxLength logic
// 2. Implement Marshall, Unmarshall
// 3. Clean up code further

// Sha2 interface
type Sha2 interface {
	HashAlgorithm() HashAlgorithm
	Init(hashAlgorithm HashAlgorithm) *Hasher
	Write(message []byte) *Hasher
	Sum() interface{}
}

// HashAlgorithm is unique type that will be enumerated
type HashAlgorithm uint32

// Hasher structure contains small number of private fields
type Hasher struct {
	fillLine        int
	finished        bool
	hash256         *[8]uint32
	hash512         *[8]uint64
	hashAlgorithm   HashAlgorithm
	lenProcessed    uint64
	m256            bool
	sha256Constants *[64]uint32
	sha512Constants *[80]uint64
	tempBlock256    *[64]byte
	tempBlock512    *[128]byte
}

// Enumerated constant for each hash algorithm
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

var bBYTESINBLOCK256 = 64 //big.NewInt(64)
var bYTESINBLOCK256 = 64
var mAXBYTESINBLOCK256 = 56

var bBYTESINBLOCK512 = 128 // big.NewInt(128)
var bYTESINBLOCK512 = 128
var mAXBYTESINBLOCK512 = 112

// New constructs a fresh instance. The HashAlgorithm algorithm can be specified here or deferred to Init().
func New(hashAlgorithm ...HashAlgorithm) *Hasher {
	var this = new(Hasher)
	this.lenProcessed = 0
	if len(hashAlgorithm) == 1 {
		this.Init(hashAlgorithm[0])
	} else if len(hashAlgorithm) > 1 {
		log.Fatal("Constructor takes 0 or 1 (HashAlgorithm) arguments")
	}
	return this
}

// Init initializes the HashAlgorithm algorithm; Only necessary if HashAlgorithm was not specified at construction.
// Initialization is (optionally) separated from construction to support setter and interface dependency
// injection scenarios.
func (hasher *Hasher) Init(hashAlgorithm HashAlgorithm) *Hasher {
	if hasher.lenProcessed > 0 { //.Cmp(big.NewInt(0)) > 0 {
		log.Fatal("Cannot switch HashAlgorithms mid-calculation")
	}
	switch hashAlgorithm {
	case Sha224:
		hasher.hash256 = &[8]uint32{ // The specific and unique initial hash for SHA-224 H[0:7]
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
		}
		hasher.tempBlock256 = &[64]byte{0}
		hasher.m256 = true // Simplifies life later
	case Sha256:
		hasher.hash256 = &[8]uint32{ // The specific and unique initial hash for SHA-256 H[0:7]
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
		}
		hasher.tempBlock256 = &[64]byte{0}
		hasher.m256 = true // Simplifies life later
	case Sha384:
		hasher.hash512 = &[8]uint64{ // The specific and unique initial hash for SHA-384 H[0:7]
			0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
			0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
		}
		hasher.tempBlock512 = &[128]byte{0}
	case Sha512:
		hasher.hash512 = &[8]uint64{ // The specific and unique initial hash for SHA-512 H[0:7]
			0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
			0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
		}
		hasher.tempBlock512 = &[128]byte{0}
	case Sha512t224:
		hasher.hash512 = &[8]uint64{ // The specific and unique initial hash for SHA-512t224 H[0:7]
			0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
			0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
		}
		hasher.tempBlock512 = &[128]byte{0}
	case Sha512t256:
		hasher.hash512 = &[8]uint64{ // The specific and unique initial hash for SHA-512t256 H[0:7]
			0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
			0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
		}
		hasher.tempBlock512 = &[128]byte{0}
	default:
		log.Fatal("Unknown (or None) hashAlgorithm")
	}

	hasher.hashAlgorithm = hashAlgorithm
	if hasher.m256 {
		hasher.sha256Constants = &[64]uint32{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
		}
	} else {
		hasher.sha512Constants = &[80]uint64{
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
			0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
			0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
			0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
			0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
			0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
			0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
			0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
			0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
			0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
			0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
			0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
			0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
		}
	}
	return hasher
}

// HashAlgorithm is the getter for the HashAlgorithm field
func (hasher *Hasher) HashAlgorithm() HashAlgorithm {
	return hasher.hashAlgorithm
}

// Write data to the hasher; Note that this can be called multiple times prior to Sum()
func (hasher *Hasher) Write(message []byte) *Hasher {
	if hasher.hashAlgorithm == None {
		log.Fatal("Initialize hash algorithm prior to writing")
	}
	if hasher.finished {
		log.Fatal("Cannot call Write() after Sum() because hasher is finished")
	}

	// If 256 && message will fit into non-empty tempBlock and still not fill it, then append it, adjust status and finish
	if hasher.m256 && len(message)+hasher.fillLine < bYTESINBLOCK256 {
		copy(hasher.tempBlock256[hasher.fillLine:hasher.fillLine+len(message)], message)
		hasher.lenProcessed += uint64(len(message))
		hasher.fillLine += len(message)
		return hasher
	}

	// If 512 && message will fit into non-empty tempBlock and still not fill it, then append it, adjust status and finish
	if !hasher.m256 && len(message)+hasher.fillLine < bYTESINBLOCK512 {
		copy(hasher.tempBlock512[hasher.fillLine:hasher.fillLine+len(message)], message)
		hasher.lenProcessed += uint64(len(message))
		hasher.fillLine += len(message)
		return hasher
	}

	// If 256 && non-empty tempBlock and message can fill it, then append it, hash it and call back with message segment
	if hasher.m256 && hasher.fillLine > 0 && len(message)+hasher.fillLine > (bYTESINBLOCK256-1) {
		copy(hasher.tempBlock256[hasher.fillLine:hasher.fillLine+(bYTESINBLOCK256-hasher.fillLine)], message)
		hasher.lenProcessed += uint64(bYTESINBLOCK256 - hasher.fillLine)
		hasher.oneBlock256(hasher.tempBlock256[:])
		var tempFill = bYTESINBLOCK256 - hasher.fillLine
		hasher.fillLine = 0
		hasher.Write(message[tempFill:]) // One-off recursion
		return hasher
	}

	// If 512 && non-empty tempBlock and message can fill it, then append it, hash it and call back with message segment
	if !hasher.m256 && hasher.fillLine > 0 && len(message)+hasher.fillLine > (bYTESINBLOCK512-1) {
		copy(hasher.tempBlock512[hasher.fillLine:hasher.fillLine+(bYTESINBLOCK512-hasher.fillLine)], message)
		hasher.lenProcessed += uint64(bYTESINBLOCK512 - hasher.fillLine)
		hasher.oneBlock512(hasher.tempBlock512[:])
		var tempFill = bYTESINBLOCK512 - hasher.fillLine
		hasher.fillLine = 0
		hasher.Write(message[tempFill:]) // One-off recursion
		return hasher
	}

	// If 256 && empty tempBlock and message > 2*block size, then hash the blocks
	var index int
	//if hasher.m256 {
	//	for (hasher.fillLine == 0) && (len(message)-index > (bYTESINBLOCK256 - 1)) {
	//		hasher.eightBlocks256(message[index : index+bYTESINBLOCK256])
	//		index += bYTESINBLOCK256
	//		hasher.lenProcessed += uint64(bBYTESINBLOCK256)
	//	}
	//}

	// If 256 && empty tempBlock and message > block size, then hash the blocks
	//var index int
	if hasher.m256 {
		for (hasher.fillLine == 0) && (len(message)-index > (bYTESINBLOCK256 - 1)) {
			hasher.eightBlocks256(message[index : index+bYTESINBLOCK256])
			index += bYTESINBLOCK256
			hasher.lenProcessed += uint64(bBYTESINBLOCK256)
		}
	} else {
		for (hasher.fillLine == 0) && (len(message)-index > (bYTESINBLOCK512 - 1)) {
			hasher.oneBlock512(message[index : index+bYTESINBLOCK512])
			index += bYTESINBLOCK512
			hasher.lenProcessed += uint64(bBYTESINBLOCK512)
		}
	}
	// If we still have a little bit of message remaining, call back
	if len(message)-index > 0 {
		hasher.Write(message[index:]) // One-off recursion
		return hasher
	}

	return hasher
}

// Sum returns the final hash calculation. Locks hash and clears temp data.
func (hasher *Hasher) Sum() interface{} {
	if !hasher.finished {
		hasher.finalize()
	}
	hasher.finished = true

	if hasher.lenProcessed > 1<<63 {
		log.Fatal("Length is too long") // Done in Sum() for performance
	}

	switch hasher.hashAlgorithm {
	case Sha224:
		var digest [28]byte
		for index := 0; index < 28; index += 4 {
			binary.BigEndian.PutUint32(digest[index:index+4], hasher.hash256[index/4])
		}
		return digest
	case Sha256:
		var digest [32]byte
		for index := 0; index < 32; index += 4 {
			binary.BigEndian.PutUint32(digest[index:index+4], hasher.hash256[index/4])
		}
		return digest
	case Sha384:
		var digest [48]byte
		for index := 0; index < 48; index += 8 {
			binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
		}
		return digest
	case Sha512:
		var digest [64]byte
		for index := 0; index < 64; index += 8 {
			binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
		}
		return digest
	case Sha512t224:
		var digest [28]byte
		for index := 0; index < 24; index += 8 {
			binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
		}
		binary.BigEndian.PutUint32(digest[24:28], uint32(hasher.hash512[3]>>32)) // Pesky left-over
		return digest
	case Sha512t256:
		var digest [32]byte
		for index := 0; index < 32; index += 8 {
			binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
		}
		return digest
	default:
		log.Fatal("Unknown (or None) hashAlgorithm")
	}
	return nil
}

func (hasher *Hasher) finalize() {

	// Finalize by hashing last block if padding will fit
	if (hasher.m256 && hasher.fillLine < mAXBYTESINBLOCK256) || (!hasher.m256 && hasher.fillLine < mAXBYTESINBLOCK512) {
		hasher.lastBlock()
	}

	// Finalize by hashing two last blocks if padding will NOT fit
	if (hasher.m256 && hasher.fillLine >= mAXBYTESINBLOCK256 && hasher.fillLine < bYTESINBLOCK256) ||
		(!hasher.m256 && hasher.fillLine >= mAXBYTESINBLOCK512 && hasher.fillLine < bYTESINBLOCK512) {
		hasher.fillBlock()
		if hasher.m256 {
			hasher.oneBlock256(hasher.tempBlock256[:])
		} else {
			hasher.oneBlock512(hasher.tempBlock512[:])
		}
		hasher.fillLine = 0
		hasher.fillBlock()
		if hasher.m256 {
			hasher.tempBlock256[hasher.fillLine] = 0
		} else {
			hasher.tempBlock512[hasher.fillLine] = 0
		}
		hasher.tagLength()
		if hasher.m256 {
			hasher.oneBlock256(hasher.tempBlock256[:])
		} else {
			hasher.oneBlock512(hasher.tempBlock512[:])
		}
	}

	// Clear working data
	hasher.fillLine = 0
	hasher.fillBlock()

}

func (hasher *Hasher) oneBlock512(message []byte) *Hasher {
	if len(message) != bYTESINBLOCK512 {
		log.Fatal("oneBlock512 got an odd sized block.")
	}
	// Message schedule
	var w [80]uint64

	// First 16 are straightforward
	for i := 0; i < 16; i++ {
		j := i * 8
		w[i] = binary.BigEndian.Uint64(message[j : j+8])
	}

	// Remaining 64 are more complicated
	for i := 16; i < 80; i++ {
		v1 := w[i-2]
		t1 := bits.RotateLeft64(v1, -19) ^ bits.RotateLeft64(v1, -61) ^ (v1 >> 6) // (4.7 -> 4.13)
		v2 := w[i-15]
		t2 := bits.RotateLeft64(v2, -1) ^ bits.RotateLeft64(v2, -8) ^ (v2 >> 7) // (4.6 -> 4.12)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}

	// Initialize working variables
	var a, b, c, d, e, f, g, h = hasher.hash512[0], hasher.hash512[1], hasher.hash512[2], hasher.hash512[3],
		hasher.hash512[4], hasher.hash512[5], hasher.hash512[6], hasher.hash512[7]

	for i := 0; i < 80; i++ {
		t1 := h + (bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41)) +
			((e & f) ^ (^e & g)) + hasher.sha512Constants[i] + w[i] // h + (4.5) + ch(e,f,g) + k + w
		t2 := (bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)) +
			((a & b) ^ (a & c) ^ (b & c)) // (4.4) + Maj(a,b,c)
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}

	hasher.hash512[0] += a
	hasher.hash512[1] += b
	hasher.hash512[2] += c
	hasher.hash512[3] += d
	hasher.hash512[4] += e
	hasher.hash512[5] += f
	hasher.hash512[6] += g
	hasher.hash512[7] += h

	return hasher

}

// Mark the end of data and fill remainder with zeros; only for tempBlocks
func (hasher *Hasher) fillBlock() {
	if hasher.m256 {
		hasher.tempBlock256[hasher.fillLine] = 128 // Set MSB
		for index := hasher.fillLine + 1; index < bYTESINBLOCK256; index++ {
			hasher.tempBlock256[index] = 0x00 // Clear MSB
		}
	} else {
		hasher.tempBlock512[hasher.fillLine] = 128 // Set MSB
		for index := hasher.fillLine + 1; index < bYTESINBLOCK512; index++ {
			hasher.tempBlock512[index] = 0x00 // Clear MSB
		}
	}
}

// Insert message length tag at the end; only for tempBlocks
func (hasher *Hasher) tagLength() {
	hasher.lenProcessed *= 8
	if hasher.m256 {
		binary.BigEndian.PutUint64(hasher.tempBlock256[mAXBYTESINBLOCK256:bYTESINBLOCK256], hasher.lenProcessed)
	} else {
		binary.BigEndian.PutUint64(hasher.tempBlock512[mAXBYTESINBLOCK512+8:bYTESINBLOCK512], hasher.lenProcessed)
		hasher.lenProcessed = hasher.lenProcessed >> 64
		binary.BigEndian.PutUint64(hasher.tempBlock512[mAXBYTESINBLOCK512:mAXBYTESINBLOCK512+8], hasher.lenProcessed)
	}
}

// Hash the very last block; only for tempBlocks
func (hasher *Hasher) lastBlock() {
	hasher.fillBlock()
	hasher.tagLength()
	if hasher.m256 {
		hasher.oneBlock256(hasher.tempBlock256[:])
	} else {
		hasher.oneBlock512(hasher.tempBlock512[:])
	}
}
