package hasher

import (
	"encoding/binary"
	"math/bits"
)

// Structure for hash256 based algorithms
type hasher256 struct {
	FillLine     int        `json:"fillLine"`
	Finished     bool       `json:"finished"`
	HashBlock256 *[8]uint32 `json:"hashBlock256"`
	LenProcessed uint64     `json:"lenProcessed"`
	TempBlock256 *[64]byte  `json:"tempBlock256"`
}

// Structure personalized for sha224
type sha224 struct {
	hasher256 `json:"hasher224"`
}

// Structure personalized for sha256
type sha256 struct {
	hasher256 `json:"hasher256"`
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

// Copy returns a deep copy
func (hasher *sha224) Copy() Hasher {
	return hasherCopy(New(Sha224), hasher)
}

// Copy returns a deep copy
func (hasher *sha256) Copy() Hasher {
	return hasherCopy(New(Sha256), hasher)
}

// HashAlgorithm returns the hash algorithm of the "object"
func (hasher *sha224) HashAlgorithm() HashAlgorithm {
	return Sha224
}

// HashAlgorithm returns the hash algorithm of the "object"
func (hasher *sha256) HashAlgorithm() HashAlgorithm {
	return Sha256
}

// InterimSum returns "the sum so far" without finalizing the original hasher
func (hasher sha224) InterimSum() interface{} {
	return hasher.Copy().Sum()
}

// InterimSum returns "the sum so far" without finalizing the original hasher
func (hasher sha256) InterimSum() interface{} {
	return hasher.Copy().Sum()
}

// Sum returns the final sum and marks the hasher as finished to prevent additional writes
func (hasher *sha224) Sum() interface{} {
	if !hasher.Finished {
		finalize256(&hasher.hasher256)
	}
	hasher.Finished = true
	var digest [28]byte
	for index := 0; index < 28; index += 4 {
		binary.BigEndian.PutUint32(digest[index:index+4], hasher.HashBlock256[index/4])
	}
	return digest
}

// Sum returns the final sum and marks the hasher as finished to prevent additional writes
func (hasher *sha256) Sum() interface{} {
	if !hasher.Finished {
		finalize256(&hasher.hasher256)
	}
	hasher.Finished = true
	var digest [32]byte
	for index := 0; index < 32; index += 4 {
		binary.BigEndian.PutUint32(digest[index:index+4], hasher.HashBlock256[index/4])
	}
	return digest
}

// Write pushes additional data into the hasher; can be called multiple times in streaming applications
func (hasher *sha224) Write(message []byte) Hasher {
	write256(&hasher.hasher256, message)
	return hasher
}

// Write pushes additional data into the hasher; can be called multiple times in streaming applications
func (hasher *sha256) Write(message []byte) Hasher {
	write256(&hasher.hasher256, message)
	return hasher
}

// init creates an initialized structure specific to the algorithm in play
func (hasher *sha224) init(hashAlgorithm HashAlgorithm) Hasher {
	hasher.LenProcessed = 0
	hasher.TempBlock256 = &[64]byte{0}
	hasher.HashBlock256 = &[8]uint32{ // The specific/unique initial conditions for SHA-224 H[0:7]
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
	}
	return hasher
}

// init creates an initialized structure specific to the algorithm in play
func (hasher *sha256) init(hashAlgorithm HashAlgorithm) Hasher {
	hasher.LenProcessed = 0
	hasher.TempBlock256 = &[64]byte{0}
	hasher.HashBlock256 = &[8]uint32{ // The specific/unique initial conditions for SHA-256 H[0:7]
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	return hasher
}

// write256 does the real work of message ingestion
func write256(hasher *hasher256, message []byte) {
	if hasher.Finished {
		LogFatal("Cannot call Write() after Sum() because the hasher has been finalized")
	}
	if hasher.LenProcessed+uint64(len(message)) < hasher.LenProcessed {
		LogFatal("Total message length of 2**64 has been exceeded")
	}

	// If message fits into non-empty tempBlock without filling it: append, adjust status and finish
	if len(message)+hasher.FillLine < bYTESINBLOCK256 {
		copy(hasher.TempBlock256[hasher.FillLine:hasher.FillLine+len(message)], message)
		hasher.LenProcessed += uint64(len(message))
		hasher.FillLine += len(message)
		return
	}

	// If message can fill non-empty tempBlock: append, hash it and call back with message remainder
	if hasher.FillLine > 0 && len(message)+hasher.FillLine > (bYTESINBLOCK256-1) {
		copy(hasher.TempBlock256[hasher.FillLine:hasher.FillLine+(bYTESINBLOCK256-hasher.FillLine)], message)
		hasher.LenProcessed += uint64(bYTESINBLOCK256 - hasher.FillLine)
		oneBlock256(hasher, hasher.TempBlock256[:])
		var tempFill = bYTESINBLOCK256 - hasher.FillLine
		hasher.FillLine = 0
		write256(hasher, message[tempFill:]) // One-off recursion
		return
	}

	// If empty tempBlock and message > block size: hash block-by-block
	var index int
	for (hasher.FillLine == 0) && (len(message)-index > (bYTESINBLOCK256 - 1)) {
		oneBlock256(hasher, message[index:index+bYTESINBLOCK256])
		index += bYTESINBLOCK256
		hasher.LenProcessed += uint64(bYTESINBLOCK256)
	}

	// If message segment remainder exists: call back
	if len(message)-index > 0 {
		write256(hasher, message[index:]) // One-off recursion
	}
}

// finalize256 finishes the calculation by padding, marking length, and hashing final block(s)
func finalize256(hasher *hasher256) {
	// Finalize by hashing last block if padding will fit
	if hasher.FillLine < mAXBYTESINBLOCK256 {
		lastBlock256(hasher)
	}

	// Finalize by hashing two last blocks if padding will NOT fit
	if hasher.FillLine >= mAXBYTESINBLOCK256 && hasher.FillLine < bYTESINBLOCK256 {
		fillBlock256(hasher)
		oneBlock256(hasher, hasher.TempBlock256[:])
		hasher.FillLine = 0
		fillBlock256(hasher)
		hasher.TempBlock256[hasher.FillLine] = 0
		tagLength256(hasher)
		oneBlock256(hasher, hasher.TempBlock256[:])
	}

	// Clear working data
	hasher.FillLine = 0
	fillBlock256(hasher)
}

// fillBlock256 sets the message-end marker and zeros the remainder
func fillBlock256(hasher *hasher256) {
	hasher.TempBlock256[hasher.FillLine] = 128 // Set MSB
	for index := hasher.FillLine + 1; index < bYTESINBLOCK256; index++ {
		hasher.TempBlock256[index] = 0x00 // Clear MSB
	}
}

// tagLength256 put the length field into the message end
func tagLength256(hasher *hasher256) {
	hasher.LenProcessed *= 8
	binary.BigEndian.PutUint64(hasher.TempBlock256[mAXBYTESINBLOCK256:bYTESINBLOCK256], hasher.LenProcessed)
}

// lastBlock256 nearly done!
func lastBlock256(hasher *hasher256) {
	fillBlock256(hasher)
	tagLength256(hasher)
	oneBlock256(hasher, hasher.TempBlock256[:])
}

// Message schedule (faster out here)
var w256 [64]uint32

// oneBlock256 does one full hash block iteration
func oneBlock256(hasher *hasher256, message []byte) {
	// First 16 w256 are straightforward
	for i := 0; i < 16; i++ {
		j := i * 4
		w256[i] = binary.BigEndian.Uint32(message[j : j+4])
	}

	// Remaining 48 w256 a little more complicated
	for i := 16; i < 64; i++ {
		v1 := w256[i-2]
		t1 := bits.RotateLeft32(v1, -17) ^ bits.RotateLeft32(v1, -19) ^ (v1 >> 10)
		v2 := w256[i-15]
		t2 := bits.RotateLeft32(v2, -7) ^ bits.RotateLeft32(v2, -18) ^ (v2 >> 3)
		w256[i] = t1 + w256[i-7] + t2 + w256[i-16]
	}

	// Initialize working variables
	var e1, e2, e3, e4, a1, a2, a3, a4 uint32
	var a, b, c, d, e, f, g, h = hasher.HashBlock256[0], hasher.HashBlock256[1], hasher.HashBlock256[2],
		hasher.HashBlock256[3], hasher.HashBlock256[4], hasher.HashBlock256[5], hasher.HashBlock256[6],
		hasher.HashBlock256[7]

	for i := 0; i < 64; i += 8 {

		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^
			bits.RotateLeft32(e, -25)) + ((e & f) ^ (^e & g)) + sha256Constants[i] + w256[i]
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^
			bits.RotateLeft32(a, -22)) + ((a & b) ^ (a & c) ^ (b & c))
		e1 = d + t1
		a1 = t1 + t2

		t1 = g + (bits.RotateLeft32(e1, -6) ^ bits.RotateLeft32(e1, -11) ^
			bits.RotateLeft32(e1, -25)) + ((e1 & e) ^ (^e1 & f)) + sha256Constants[i+1] + w256[i+1]
		t2 = (bits.RotateLeft32(a1, -2) ^ bits.RotateLeft32(a1, -13) ^
			bits.RotateLeft32(a1, -22)) + ((a1 & a) ^ (a1 & b) ^ (a & b))
		e2 = c + t1
		a2 = t1 + t2

		t1 = f + (bits.RotateLeft32(e2, -6) ^ bits.RotateLeft32(e2, -11) ^
			bits.RotateLeft32(e2, -25)) + ((e2 & e1) ^ (^e2 & e)) + sha256Constants[i+2] + w256[i+2]
		t2 = (bits.RotateLeft32(a2, -2) ^ bits.RotateLeft32(a2, -13) ^
			bits.RotateLeft32(a2, -22)) + ((a2 & a1) ^ (a2 & a) ^ (a1 & a))
		e3 = b + t1
		a3 = t1 + t2

		t1 = e + (bits.RotateLeft32(e3, -6) ^ bits.RotateLeft32(e3, -11) ^
			bits.RotateLeft32(e3, -25)) + ((e3 & e2) ^ (^e3 & e1)) + sha256Constants[i+3] + w256[i+3]
		t2 = (bits.RotateLeft32(a3, -2) ^ bits.RotateLeft32(a3, -13) ^
			bits.RotateLeft32(a3, -22)) + ((a3 & a2) ^ (a3 & a1) ^ (a2 & a1))
		e4 = a + t1
		a4 = t1 + t2

		t1 = e1 + (bits.RotateLeft32(e4, -6) ^ bits.RotateLeft32(e4, -11) ^
			bits.RotateLeft32(e4, -25)) + ((e4 & e3) ^ (^e4 & e2)) + sha256Constants[i+4] + w256[i+4]
		t2 = (bits.RotateLeft32(a4, -2) ^ bits.RotateLeft32(a4, -13) ^
			bits.RotateLeft32(a4, -22)) + ((a4 & a3) ^ (a4 & a2) ^ (a3 & a2))
		h = a1 + t1
		d = t1 + t2

		t1 = e2 + (bits.RotateLeft32(h, -6) ^ bits.RotateLeft32(h, -11) ^
			bits.RotateLeft32(h, -25)) + ((h & e4) ^ (^h & e3)) + sha256Constants[i+5] + w256[i+5]
		t2 = (bits.RotateLeft32(d, -2) ^ bits.RotateLeft32(d, -13) ^
			bits.RotateLeft32(d, -22)) + ((d & a4) ^ (d & a3) ^ (a4 & a3))
		g = a2 + t1
		c = t1 + t2

		t1 = e3 + (bits.RotateLeft32(g, -6) ^ bits.RotateLeft32(g, -11) ^
			bits.RotateLeft32(g, -25)) + ((g & h) ^ (^g & e4)) + sha256Constants[i+6] + w256[i+6]
		t2 = (bits.RotateLeft32(c, -2) ^ bits.RotateLeft32(c, -13) ^
			bits.RotateLeft32(c, -22)) + ((c & d) ^ (c & a4) ^ (d & a4))
		f = a3 + t1
		b = t1 + t2

		t1 = e4 + (bits.RotateLeft32(f, -6) ^ bits.RotateLeft32(f, -11) ^
			bits.RotateLeft32(f, -25)) + ((f & g) ^ (^f & h)) + sha256Constants[i+7] + w256[i+7]
		t2 = (bits.RotateLeft32(b, -2) ^ bits.RotateLeft32(b, -13) ^
			bits.RotateLeft32(b, -22)) + ((b & c) ^ (b & d) ^ (c & d))
		e = a4 + t1
		a = t1 + t2
	}

	hasher.HashBlock256[0] += a
	hasher.HashBlock256[1] += b
	hasher.HashBlock256[2] += c
	hasher.HashBlock256[3] += d
	hasher.HashBlock256[4] += e
	hasher.HashBlock256[5] += f
	hasher.HashBlock256[6] += g
	hasher.HashBlock256[7] += h
}
