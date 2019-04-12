package hasher

import (
	"encoding/binary"
	"log"
	"math/bits"
)

type hasher512 struct {
	fillLine     int
	hash512      *[8]uint64
	lenProcessed uint64
	tempBlock512 *[128]byte
	finished     bool
}

type sha384 struct {
	hasher512
}

type sha512 struct {
	hasher512
}

type sha512t224 struct {
	hasher512
}

type sha512t256 struct {
	hasher512
}

const (
	bYTESINBLOCK512    int = 128
	mAXBYTESINBLOCK512 int = 112
)

var sha512Constants = &[80]uint64{
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

func (hasher *sha384) Init(hashAlgorithm HashAlgorithm) Hasher {
	if hasher.lenProcessed > 0 {
		log.Fatal("Cannot switch HashAlgorithms mid-calculation")
	}
	hasher.lenProcessed = 0
	hasher.tempBlock512 = &[128]byte{0}
	hasher.hash512 = &[8]uint64{ // The specific and unique initial hasher256 for SHA-384 H[0:7]
		0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
		0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
	}
	return hasher
}

func (hasher *sha512) Init(hashAlgorithm HashAlgorithm) Hasher {
	if hasher.lenProcessed > 0 {
		log.Fatal("Cannot switch HashAlgorithms mid-calculation")
	}
	hasher.lenProcessed = 0
	hasher.tempBlock512 = &[128]byte{0}
	hasher.hash512 = &[8]uint64{ // The specific and unique initial hasher256 for SHA-512 H[0:7]
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	return hasher
}

func (hasher *sha512t224) Init(hashAlgorithm HashAlgorithm) Hasher {
	if hasher.lenProcessed > 0 {
		log.Fatal("Cannot switch HashAlgorithms mid-calculation")
	}
	hasher.lenProcessed = 0
	hasher.tempBlock512 = &[128]byte{0}
	hasher.hash512 = &[8]uint64{ // The specific and unique initial hasher256 for SHA-512t224 H[0:7]
		0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
		0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
	}
	return hasher
}

func (hasher *sha512t256) Init(hashAlgorithm HashAlgorithm) Hasher {
	if hasher.lenProcessed > 0 {
		log.Fatal("Cannot switch HashAlgorithms mid-calculation")
	}
	hasher.lenProcessed = 0
	hasher.tempBlock512 = &[128]byte{0}
	hasher.hash512 = &[8]uint64{ // The specific and unique initial hasher256 for SHA-512t256 H[0:7]
		0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
		0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
	}
	return hasher
}

func (hasher *sha384) HashAlgorithm() HashAlgorithm {
	return Sha384
}

func (hasher *sha512) HashAlgorithm() HashAlgorithm {
	return Sha512
}

func (hasher *sha512t224) HashAlgorithm() HashAlgorithm {
	return Sha512t224
}

func (hasher *sha512t256) HashAlgorithm() HashAlgorithm {
	return Sha512t256
}

func (hasher *sha384) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

func (hasher *sha512) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

func (hasher *sha512t224) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

func (hasher *sha512t256) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

func (hasher *sha384) Sum() interface{} {
	if !hasher.finished {
		finalize512(&hasher.hasher512)
	}
	hasher.finished = true
	var digest [48]byte
	for index := 0; index < 48; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
	}
	return digest
}

func (hasher *sha512) Sum() interface{} {
	if !hasher.finished {
		finalize512(&hasher.hasher512)
	}
	hasher.finished = true
	var digest [64]byte
	for index := 0; index < 64; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
	}
	return digest
}

func (hasher *sha512t224) Sum() interface{} {
	if !hasher.finished {
		finalize512(&hasher.hasher512)
	}
	hasher.finished = true
	var digest [28]byte
	for index := 0; index < 24; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
	}
	binary.BigEndian.PutUint32(digest[24:28], uint32(hasher.hash512[3]>>32)) // Pesky left-over
	return digest
}

func (hasher *sha512t256) Sum() interface{} {
	if !hasher.finished {
		finalize512(&hasher.hasher512)
	}
	hasher.finished = true
	var digest [32]byte
	for index := 0; index < 32; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.hash512[index/8])
	}
	return digest
}

func write512(hasher *hasher512, message []byte) {
	if hasher.finished {
		log.Fatal("Cannot call Write() after Sum() because hasher is finished")
	}

	// If message will fit into non-empty tempBlock and still not fill it, then append it, adjust status and finish
	if len(message)+hasher.fillLine < bYTESINBLOCK512 {
		copy(hasher.tempBlock512[hasher.fillLine:hasher.fillLine+len(message)], message)
		hasher.lenProcessed += uint64(len(message))
		hasher.fillLine += len(message)
		return
	}

	// If non-empty tempBlock and message can fill it, then append it, hasher256 it and call back with message segment
	if hasher.fillLine > 0 && len(message)+hasher.fillLine > (bYTESINBLOCK512-1) {
		copy(hasher.tempBlock512[hasher.fillLine:hasher.fillLine+(bYTESINBLOCK512-hasher.fillLine)], message)
		hasher.lenProcessed += uint64(bYTESINBLOCK512 - hasher.fillLine)
		oneBlock512(hasher, hasher.tempBlock512[:])
		var tempFill = bYTESINBLOCK512 - hasher.fillLine
		hasher.fillLine = 0
		write512(hasher, message[tempFill:]) // One-off recursion
		return
	}

	// If empty tempBlock and message > block size, then hasher256 the blocks
	var index int
	for (hasher.fillLine == 0) && (len(message)-index > (bYTESINBLOCK512 - 1)) {
		oneBlock512(hasher, message[index:index+bYTESINBLOCK512])
		index += bYTESINBLOCK512
		hasher.lenProcessed += uint64(bYTESINBLOCK512)
	}

	// If we still have a little bit of message remaining, call back
	if len(message)-index > 0 {
		write512(hasher, message[index:]) // One-off recursion
		return
	}

	return
}

func finalize512(hasher *hasher512) {

	// Finalize by hashing last block if padding will fit
	if hasher.fillLine < mAXBYTESINBLOCK512 {
		lastBlock512(hasher)
	}

	// Finalize by hashing two last blocks if padding will NOT fit
	if hasher.fillLine >= mAXBYTESINBLOCK512 && hasher.fillLine < bYTESINBLOCK512 {
		fillBlock512(hasher)
		oneBlock512(hasher, hasher.tempBlock512[:])
		hasher.fillLine = 0
		fillBlock512(hasher)
		hasher.tempBlock512[hasher.fillLine] = 0
		tagLength512(hasher)
		oneBlock512(hasher, hasher.tempBlock512[:])
	}

	// Clear working data
	hasher.fillLine = 0
	fillBlock512(hasher)
}

// Mark the end of data and fill remainder with zeros; only for tempBlocks
func fillBlock512(hasher *hasher512) {
	hasher.tempBlock512[hasher.fillLine] = 128 // Set MSB
	for index := hasher.fillLine + 1; index < bYTESINBLOCK512; index++ {
		hasher.tempBlock512[index] = 0x00 // Clear MSB
	}
}

// Insert message length tag at the end; only for tempBlocks
func tagLength512(hasher *hasher512) {
	hasher.lenProcessed *= 8
	binary.BigEndian.PutUint64(hasher.tempBlock512[mAXBYTESINBLOCK512+8:bYTESINBLOCK512], hasher.lenProcessed)
}

// Hash the very last block; only for tempBlocks
func lastBlock512(hasher *hasher512) {
	fillBlock512(hasher)
	tagLength512(hasher)
	oneBlock512(hasher, hasher.tempBlock512[:])
}

// Message schedule
var w512 [80]uint64

func oneBlock512(hasher *hasher512, message []byte) {
	if len(message) != bYTESINBLOCK512 {
		log.Fatal("oneBlock512 got an odd sized block.")
	}

	// First 16 are straightforward
	for i := 0; i < 16; i++ {
		j := i * 8
		w512[i] = binary.BigEndian.Uint64(message[j : j+8])
	}

	// Remaining 64 are more complicated
	for i := 16; i < 80; i++ {
		v1 := w512[i-2]
		t1 := bits.RotateLeft64(v1, -19) ^ bits.RotateLeft64(v1, -61) ^ (v1 >> 6)
		v2 := w512[i-15]
		t2 := bits.RotateLeft64(v2, -1) ^ bits.RotateLeft64(v2, -8) ^ (v2 >> 7)
		w512[i] = t1 + w512[i-7] + t2 + w512[i-16]
	}

	// Initialize working variables
	var a, b, c, d, e, f, g, h, e1, e2, e3, e4, a1, a2, a3, a4 uint64
	a, b, c, d, e, f, g, h = hasher.hash512[0], hasher.hash512[1], hasher.hash512[2], hasher.hash512[3],
		hasher.hash512[4], hasher.hash512[5], hasher.hash512[6], hasher.hash512[7]

	for i := 0; i < 80; i = i + 8 {
		t1 := h + (bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41)) +
			((e & f) ^ (^e & g)) + sha512Constants[i] + w512[i]
		t2 := (bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)) +
			((a & b) ^ (a & c) ^ (b & c))
		e1 = d + t1
		a1 = t1 + t2

		t1 = g + (bits.RotateLeft64(e1, -14) ^ bits.RotateLeft64(e1, -18) ^ bits.RotateLeft64(e1, -41)) +
			((e1 & e) ^ (^e1 & f)) + sha512Constants[i+1] + w512[i+1]
		t2 = (bits.RotateLeft64(a1, -28) ^ bits.RotateLeft64(a1, -34) ^ bits.RotateLeft64(a1, -39)) +
			((a1 & a) ^ (a1 & b) ^ (a & b))
		e2 = c + t1
		a2 = t1 + t2

		t1 = f + (bits.RotateLeft64(e2, -14) ^ bits.RotateLeft64(e2, -18) ^ bits.RotateLeft64(e2, -41)) +
			((e2 & e1) ^ (^e2 & e)) + sha512Constants[i+2] + w512[i+2]
		t2 = (bits.RotateLeft64(a2, -28) ^ bits.RotateLeft64(a2, -34) ^ bits.RotateLeft64(a2, -39)) +
			((a2 & a1) ^ (a2 & a) ^ (a1 & a))
		e3 = b + t1
		a3 = t1 + t2

		t1 = e + (bits.RotateLeft64(e3, -14) ^ bits.RotateLeft64(e3, -18) ^ bits.RotateLeft64(e3, -41)) +
			((e3 & e2) ^ (^e3 & e1)) + sha512Constants[i+3] + w512[i+3]
		t2 = (bits.RotateLeft64(a3, -28) ^ bits.RotateLeft64(a3, -34) ^ bits.RotateLeft64(a3, -39)) +
			((a3 & a2) ^ (a3 & a1) ^ (a2 & a1))
		e4 = a + t1
		a4 = t1 + t2

		t1 = e1 + (bits.RotateLeft64(e4, -14) ^ bits.RotateLeft64(e4, -18) ^ bits.RotateLeft64(e4, -41)) +
			((e4 & e3) ^ (^e4 & e2)) + sha512Constants[i+4] + w512[i+4]
		t2 = (bits.RotateLeft64(a4, -28) ^ bits.RotateLeft64(a4, -34) ^ bits.RotateLeft64(a4, -39)) +
			((a4 & a3) ^ (a4 & a2) ^ (a3 & a2))
		h = a1 + t1
		d = t1 + t2

		t1 = e2 + (bits.RotateLeft64(h, -14) ^ bits.RotateLeft64(h, -18) ^ bits.RotateLeft64(h, -41)) +
			((h & e4) ^ (^h & e3)) + sha512Constants[i+5] + w512[i+5]
		t2 = (bits.RotateLeft64(d, -28) ^ bits.RotateLeft64(d, -34) ^ bits.RotateLeft64(d, -39)) +
			((d & a4) ^ (d & a3) ^ (a4 & a3))
		g = a2 + t1
		c = t1 + t2

		t1 = e3 + (bits.RotateLeft64(g, -14) ^ bits.RotateLeft64(g, -18) ^ bits.RotateLeft64(g, -41)) +
			((g & h) ^ (^g & e4)) + sha512Constants[i+6] + w512[i+6]
		t2 = (bits.RotateLeft64(c, -28) ^ bits.RotateLeft64(c, -34) ^ bits.RotateLeft64(c, -39)) +
			((c & d) ^ (c & a4) ^ (d & a4))
		f = a3 + t1
		b = t1 + t2

		t1 = e4 + (bits.RotateLeft64(f, -14) ^ bits.RotateLeft64(f, -18) ^ bits.RotateLeft64(f, -41)) +
			((f & g) ^ (^f & h)) + sha512Constants[i+7] + w512[i+7]
		t2 = (bits.RotateLeft64(b, -28) ^ bits.RotateLeft64(b, -34) ^ bits.RotateLeft64(b, -39)) +
			((b & c) ^ (b & d) ^ (c & d))
		e = a4 + t1
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
}
