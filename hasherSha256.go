package hasher

import (
	"encoding/binary"
	"log"
	"math/bits"
)

type hasher256 struct {
	fillLine     int
	hash256      *[8]uint32
	lenProcessed uint64
	tempBlock256 *[64]byte
	finished     bool
}

type sha224 struct {
	hasher256
}

type sha256 struct {
	hasher256
}

const (
	bYTESINBLOCK256    int = 64
	mAXBYTESINBLOCK256 int = 56
)

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

func (hasher *sha224) Init(hashAlgorithm HashAlgorithm) Hasher {
	if hasher.lenProcessed > 0 {
		log.Fatal("Cannot switch HashAlgorithms mid-calculation")
	}
	hasher.lenProcessed = 0
	hasher.tempBlock256 = &[64]byte{0}
	hasher.hash256 = &[8]uint32{ // The specific and unique initial hasher256 for SHA-224 H[0:7]
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
	}
	return hasher
}

func (hasher *sha256) Init(hashAlgorithm HashAlgorithm) Hasher {
	if hasher.lenProcessed > 0 {
		log.Fatal("Cannot switch HashAlgorithms mid-calculation")
	}
	hasher.lenProcessed = 0
	hasher.tempBlock256 = &[64]byte{0}
	hasher.hash256 = &[8]uint32{ // The specific and unique initial hasher256 for SHA-256 H[0:7]
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	return hasher
}

func (hasher *sha224) HashAlgorithm() HashAlgorithm {
	return Sha224
}

func (hasher *sha256) HashAlgorithm() HashAlgorithm {
	return Sha256
}

func (hasher *sha224) Write(message []byte) Hasher {
	write256(&hasher.hasher256, message)
	return hasher
}

func (hasher *sha256) Write(message []byte) Hasher {
	write256(&hasher.hasher256, message)
	return hasher
}

func (hasher *sha224) Sum() interface{} {
	if !hasher.finished {
		finalize256(&hasher.hasher256)
	}
	hasher.finished = true
	var digest [28]byte
	for index := 0; index < 28; index += 4 {
		binary.BigEndian.PutUint32(digest[index:index+4], hasher.hash256[index/4])
	}
	return digest
}

func (hasher *sha256) Sum() interface{} {
	if !hasher.finished {
		finalize256(&hasher.hasher256)
	}
	hasher.finished = true
	var digest [32]byte
	for index := 0; index < 32; index += 4 {
		binary.BigEndian.PutUint32(digest[index:index+4], hasher.hash256[index/4])
	}
	return digest

}

func write256(hasher *hasher256, message []byte) {
	if hasher.finished {
		log.Fatal("Cannot call Write() after Sum() because hasher is finished")
	}

	// If message will fit into non-empty tempBlock and still not fill it, then append it, adjust status and finish
	if len(message)+hasher.fillLine < bYTESINBLOCK256 {
		copy(hasher.tempBlock256[hasher.fillLine:hasher.fillLine+len(message)], message)
		hasher.lenProcessed += uint64(len(message))
		hasher.fillLine += len(message)
		return
	}

	// If non-empty tempBlock and message can fill it, then append it, hasher256 it and call back with message segment
	if hasher.fillLine > 0 && len(message)+hasher.fillLine > (bYTESINBLOCK256-1) {
		copy(hasher.tempBlock256[hasher.fillLine:hasher.fillLine+(bYTESINBLOCK256-hasher.fillLine)], message)
		hasher.lenProcessed += uint64(bYTESINBLOCK256 - hasher.fillLine)
		oneBlock256(hasher, hasher.tempBlock256[:])
		var tempFill = bYTESINBLOCK256 - hasher.fillLine
		hasher.fillLine = 0
		write256(hasher, message[tempFill:]) // One-off recursion
		return
	}

	// If empty tempBlock and message > block size, then hasher256 the blocks
	var index int
	for (hasher.fillLine == 0) && (len(message)-index > (bYTESINBLOCK256 - 1)) {
		oneBlock256(hasher, message[index:index+bYTESINBLOCK256])
		index += bYTESINBLOCK256
		hasher.lenProcessed += uint64(bYTESINBLOCK256)
	}

	// If we still have a little bit of message remaining, call back
	if len(message)-index > 0 {
		write256(hasher, message[index:]) // One-off recursion
	}
}

func finalize256(hasher *hasher256) {

	// Finalize by hashing last block if padding will fit
	if hasher.fillLine < mAXBYTESINBLOCK256 {
		lastBlock256(hasher)
	}

	// Finalize by hashing two last blocks if padding will NOT fit
	if hasher.fillLine >= mAXBYTESINBLOCK256 && hasher.fillLine < bYTESINBLOCK256 {
		fillBlock256(hasher)
		oneBlock256(hasher, hasher.tempBlock256[:])

		hasher.fillLine = 0
		fillBlock256(hasher)
		hasher.tempBlock256[hasher.fillLine] = 0

		tagLength256(hasher)
		oneBlock256(hasher, hasher.tempBlock256[:])

	}

	// Clear working data
	hasher.fillLine = 0
	fillBlock256(hasher)
}

func fillBlock256(hasher *hasher256) {
	hasher.tempBlock256[hasher.fillLine] = 128 // Set MSB
	for index := hasher.fillLine + 1; index < bYTESINBLOCK256; index++ {
		hasher.tempBlock256[index] = 0x00 // Clear MSB
	}
}

func tagLength256(hasher *hasher256) {
	hasher.lenProcessed *= 8
	binary.BigEndian.PutUint64(hasher.tempBlock256[mAXBYTESINBLOCK256:bYTESINBLOCK256], hasher.lenProcessed)

}

func lastBlock256(hasher *hasher256) {
	fillBlock256(hasher)
	tagLength256(hasher)
	oneBlock256(hasher, hasher.tempBlock256[:])
}

// Message schedule
var w [64]uint32

func oneBlock256(hasher *hasher256, message []byte) {
	if len(message) != bYTESINBLOCK256 {
		log.Fatal("eightBlocks256 got an odd sized block.")
	}

	// First 16 w are straightforward
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = binary.BigEndian.Uint32(message[j : j+4])
	}

	// Remaining 48 w are more complicated
	for i := 16; i < 64; i++ {
		v1 := w[i-2]
		t1 := bits.RotateLeft32(v1, -17) ^ bits.RotateLeft32(v1, -19) ^ (v1 >> 10)
		v2 := w[i-15]
		t2 := bits.RotateLeft32(v2, -7) ^ bits.RotateLeft32(v2, -18) ^ (v2 >> 3)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}

	// Initialize working variables
	var a, b, c, d, e, f, g, h, e1, e2, e3, e4, a1, a2, a3, a4 uint32
	a, b, c, d, e, f, g, h = hasher.hash256[0], hasher.hash256[1], hasher.hash256[2], hasher.hash256[3],
		hasher.hash256[4], hasher.hash256[5], hasher.hash256[6], hasher.hash256[7]

	for i := 0; i < 64; i += 8 {

		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) +
			((e & f) ^ (^e & g)) + sha256Constants[i] + w[i]
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) +
			((a & b) ^ (a & c) ^ (b & c))
		e1 = d + t1
		a1 = t1 + t2

		t1 = g + (bits.RotateLeft32(e1, -6) ^ bits.RotateLeft32(e1, -11) ^ bits.RotateLeft32(e1, -25)) +
			((e1 & e) ^ (^e1 & f)) + sha256Constants[i+1] + w[i+1]
		t2 = (bits.RotateLeft32(a1, -2) ^ bits.RotateLeft32(a1, -13) ^ bits.RotateLeft32(a1, -22)) +
			((a1 & a) ^ (a1 & b) ^ (a & b))
		e2 = c + t1
		a2 = t1 + t2

		t1 = f + (bits.RotateLeft32(e2, -6) ^ bits.RotateLeft32(e2, -11) ^ bits.RotateLeft32(e2, -25)) +
			((e2 & e1) ^ (^e2 & e)) + sha256Constants[i+2] + w[i+2]
		t2 = (bits.RotateLeft32(a2, -2) ^ bits.RotateLeft32(a2, -13) ^ bits.RotateLeft32(a2, -22)) +
			((a2 & a1) ^ (a2 & a) ^ (a1 & a))
		e3 = b + t1
		a3 = t1 + t2

		t1 = e + (bits.RotateLeft32(e3, -6) ^ bits.RotateLeft32(e3, -11) ^ bits.RotateLeft32(e3, -25)) +
			((e3 & e2) ^ (^e3 & e1)) + sha256Constants[i+3] + w[i+3]
		t2 = (bits.RotateLeft32(a3, -2) ^ bits.RotateLeft32(a3, -13) ^ bits.RotateLeft32(a3, -22)) +
			((a3 & a2) ^ (a3 & a1) ^ (a2 & a1))
		e4 = a + t1
		a4 = t1 + t2

		t1 = e1 + (bits.RotateLeft32(e4, -6) ^ bits.RotateLeft32(e4, -11) ^ bits.RotateLeft32(e4, -25)) +
			((e4 & e3) ^ (^e4 & e2)) + sha256Constants[i+4] + w[i+4]
		t2 = (bits.RotateLeft32(a4, -2) ^ bits.RotateLeft32(a4, -13) ^ bits.RotateLeft32(a4, -22)) +
			((a4 & a3) ^ (a4 & a2) ^ (a3 & a2))
		h = a1 + t1
		d = t1 + t2

		t1 = e2 + (bits.RotateLeft32(h, -6) ^ bits.RotateLeft32(h, -11) ^ bits.RotateLeft32(h, -25)) +
			((h & e4) ^ (^h & e3)) + sha256Constants[i+5] + w[i+5]
		t2 = (bits.RotateLeft32(d, -2) ^ bits.RotateLeft32(d, -13) ^ bits.RotateLeft32(d, -22)) +
			((d & a4) ^ (d & a3) ^ (a4 & a3))
		g = a2 + t1
		c = t1 + t2

		t1 = e3 + (bits.RotateLeft32(g, -6) ^ bits.RotateLeft32(g, -11) ^ bits.RotateLeft32(g, -25)) +
			((g & h) ^ (^g & e4)) + sha256Constants[i+6] + w[i+6]
		t2 = (bits.RotateLeft32(c, -2) ^ bits.RotateLeft32(c, -13) ^ bits.RotateLeft32(c, -22)) +
			((c & d) ^ (c & a4) ^ (d & a4))
		f = a3 + t1
		b = t1 + t2

		t1 = e4 + (bits.RotateLeft32(f, -6) ^ bits.RotateLeft32(f, -11) ^ bits.RotateLeft32(f, -25)) +
			((f & g) ^ (^f & h)) + sha256Constants[i+7] + w[i+7]
		t2 = (bits.RotateLeft32(b, -2) ^ bits.RotateLeft32(b, -13) ^ bits.RotateLeft32(b, -22)) +
			((b & c) ^ (b & d) ^ (c & d))
		e = a4 + t1
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
}
