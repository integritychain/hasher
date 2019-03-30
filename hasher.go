// Package implements the full SHA2 family of secure hash algorithms from FIPS PUB 180-4.
// It features a fluent interface for easy and flexible usage, maximal encapsulation for isolation and
// maintainability, multi-step hashing for large or streaming structures, and is compatible with dependency
// injection strategies to simplify testability.
package hasher

import (
	"log"
	"math/bits"
)

// TODO
// 1. Revisit names of constants, how they are allocated etc
// 2. Finish documentation - individual functions
// 3. Implement elaborate tests (incl examples)
// 4. Start implementing functionality

// A unique type for specifying the hash algorithms
type HashType uint32

type Hasher struct {
	hashAlgorithm HashType
	lenProcessed  uint64
	tempBlock     [64]byte
	fillLine      uint32
	hash256       *[8]uint32 // TODO: Single pointer doable?
	hash512       *[8]uint64
	finished      bool
}

// Enumerated constant for each hash algorithm
const (
	None       HashType = iota
	Sha224     HashType = iota
	Sha256     HashType = iota
	Sha384     HashType = iota
	Sha512     HashType = iota
	Sha512t224 HashType = iota
	Sha512t256 HashType = iota
)

// SHA-224 and SHA-256 share these constants totalling 256bits
var sha256Constants = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 share these constants totalling 512bits
var sha512Constants = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

// The specific and unique initial hash for SHA-224 H[0:7]
var sha224InitialHash = [8]uint32{
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
}

// The specific and unique initial hash for SHA-256 H[0:7]
var sha256InitialHash = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// The specific and unique initial hash for SHA-384 H[0:7]
var sha384InitialHash = [8]uint64{
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
}

// The specific and unique initial hash for SHA-512 H[0:7]
var sha512InitialHash = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// The specific and unique initial hash for SHA-512/224 H[0:7]
var sha512t224InitialHash = [8]uint64{
	0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
	0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
}

// The specific and unique initial hash for SHA-512/256 H[0:7]
var sha512t256InitialHash = [8]uint64{
	0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
	0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
}

// New constructs a fresh instance. The specific algorithm HashType can be passed here or deferred to Init.
func New(hashAlgorithm ...HashType) *Hasher {
	var this = new(Hasher)
	if len(hashAlgorithm) == 1 {
		this.Init(hashAlgorithm[0])
	}
	return this
}

// Init does initializes specific algorithm for a particular HashType. This function only needs to be used when the call to New did not specify the specific algorithm.
func (hasher *Hasher) Init(hashAlgorithm HashType) *Hasher {
	switch hashAlgorithm {
	case Sha224: // 0 to 7
		var temp = sha224InitialHash
		hasher.hash256 = &temp
	case Sha256:
		var temp = sha256InitialHash
		hasher.hash256 = &temp
	case Sha384:
		var temp = sha384InitialHash
		hasher.hash512 = &temp
	case Sha512:
		var temp = sha512InitialHash
		hasher.hash512 = &temp
	case Sha512t224:
		var temp = sha512t224InitialHash
		hasher.hash512 = &temp
	case Sha512t256:
		var temp = sha512t256InitialHash
		hasher.hash512 = &temp
	default:
		log.Fatal("Unknown hashAlgorithm")
	}
	hasher.hashAlgorithm = hashAlgorithm
	return hasher
}

// HashAlgorithm does something, eh?
func (hasher *Hasher) HashAlgorithm() HashType {
	return hasher.hashAlgorithm
}

func (hasher *Hasher) oneBlock(message []byte) *Hasher {
	if len(message) != 64 {
		log.Fatal("oneBlock got an odd sized block.")
	}
	// Calculate message schedule of 64 W's
	var w [64]uint32

	// First 16 are straightforward
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = uint32(message[j])<<24 | uint32(message[j+1])<<16 | uint32(message[j+2])<<8 | uint32(message[j+3]) // Assemble bytes into words
	}

	// Remaining 48 are more complicated
	for i := 16; i < 64; i++ {
		v1 := w[i-2]
		t1 := bits.RotateLeft32(v1, -17) ^ bits.RotateLeft32(v1, -19) ^ (v1 >> 10) // (4.7)
		v2 := w[i-15]
		t2 := bits.RotateLeft32(v2, -7) ^ bits.RotateLeft32(v2, -18) ^ (v2 >> 3) // (4.6)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}

	// Initialize working variables
	var a, b, c, d, e, f, g, h = hasher.hash256[0], hasher.hash256[1], hasher.hash256[2], hasher.hash256[3],
		hasher.hash256[4], hasher.hash256[5], hasher.hash256[6], hasher.hash256[7]

	for i := 0; i < 64; i++ {
		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) + ((e & f) ^ (^e & g)) + sha256Constants[i] + w[i] // h + (4.5) + ch(e,f,g) + k + w
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) + ((a & b) ^ (a & c) ^ (b & c))                        // (4.4) + Maj(a,b,c)
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}

	hasher.hash256[0] += a
	hasher.hash256[1] += b
	hasher.hash256[2] += c
	hasher.hash256[3] += d
	hasher.hash256[4] += e
	hasher.hash256[5] += f
	hasher.hash256[6] += g
	hasher.hash256[7] += h

	return hasher

}

func (hasher *Hasher) lastBlock(message []byte) *Hasher {

	var lastBlock [64]byte
	len1 := copy(lastBlock[:], message)
	if len1 > 1 {
		lastBlock[len1] = 128
	}
	//lastBlock[63] = (byte)(len&0xFF) * 8
	//x := hasher.lenProcessed.Bytes()
	if len1 < 56 {
		if hasher.lenProcessed > 256 {
			lastBlock[63] = byte(hasher.lenProcessed)
			lastBlock[62] = byte(hasher.lenProcessed >> 8)
		} else {
			lastBlock[63] = byte(hasher.lenProcessed)
		}
	}
	return hasher.oneBlock(lastBlock[:])

}

func (hasher *Hasher) Write(message []byte) *Hasher {

	var index int

	for (hasher.fillLine == 0) && (len(message)-index > 63) {
		hasher.oneBlock(message[index : index+64])
		index += 64
		hasher.lenProcessed += 64
	}

	// Move the entire message into the temp block if there is space
	var x = uint32(len(message) - index)
	var tempLen = hasher.fillLine + x
	if tempLen > 0 && tempLen < 64 {
		for i := 0; i < len(message)-index; i++ {
			//for i, v := range message {

			hasher.tempBlock[hasher.fillLine+uint32(i)] = message[index+i]
		}
		hasher.fillLine += uint32(len(message) - index)
		hasher.lenProcessed += uint64(len(message) - index)
	}

	return hasher
}

func (hasher *Hasher) Sum() interface{} {
	if hasher.fillLine >= 0 && hasher.fillLine < 56 {
		hasher.tempBlock[hasher.fillLine] = 128
		for index := hasher.fillLine + 1; index < 56; index++ {
			hasher.tempBlock[index] = 0x00
		}
		hasher.lenProcessed *= 8

		// Set trailing 128 bits
		hasher.tempBlock[63] = byte(hasher.lenProcessed)
		hasher.tempBlock[62] = byte(hasher.lenProcessed >> 8)
		hasher.tempBlock[61] = byte(hasher.lenProcessed >> 16)
		hasher.tempBlock[60] = byte(hasher.lenProcessed >> 24)
		hasher.tempBlock[59] = byte(hasher.lenProcessed >> 32)
		hasher.tempBlock[58] = byte(hasher.lenProcessed >> 40)
		hasher.tempBlock[57] = byte(hasher.lenProcessed >> 48)
		hasher.tempBlock[56] = byte(hasher.lenProcessed >> 56)

		hasher.oneBlock(hasher.tempBlock[:])
	}

	if hasher.fillLine > 55 && hasher.fillLine < 64 { //|| hasher.fillLine == 0 {
		hasher.tempBlock[hasher.fillLine] = 128
		for index := hasher.fillLine + 1; index < 64; index++ {
			hasher.tempBlock[index] = 0x00
		}
		hasher.oneBlock(hasher.tempBlock[:])
		hasher.fillLine = 0
		for index := hasher.fillLine; index < 60; index++ {
			hasher.tempBlock[index] = 0x00
		}
		hasher.lenProcessed *= 8

		// Set trailing 128 bits
		hasher.tempBlock[63] = byte(hasher.lenProcessed)
		hasher.tempBlock[62] = byte(hasher.lenProcessed >> 8)
		hasher.tempBlock[61] = byte(hasher.lenProcessed >> 16)
		hasher.tempBlock[60] = byte(hasher.lenProcessed >> 24)
		hasher.tempBlock[59] = byte(hasher.lenProcessed >> 32)
		hasher.tempBlock[58] = byte(hasher.lenProcessed >> 40)
		hasher.tempBlock[57] = byte(hasher.lenProcessed >> 48)
		hasher.tempBlock[56] = byte(hasher.lenProcessed >> 56)

		hasher.oneBlock(hasher.tempBlock[:])
	}

	if hasher.hashAlgorithm == Sha224 || hasher.hashAlgorithm == Sha256 {
		var digest [32]byte
		for i, s := range hasher.hash256 {
			digest[i*4] = byte(s >> 24)
			digest[i*4+1] = byte(s >> 16)
			digest[i*4+2] = byte(s >> 8)
			digest[i*4+3] = byte(s)
		}
		return digest
	}
	return nil
}
