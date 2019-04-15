package hasher

import (
	"encoding/binary"
	"math/bits"
)

// Structure for hash256 based algorithms
type hasher512 struct {
	FillLine     int        `json:"fillLine"`
	Finished     bool       `json:"finished"`
	HashBlock512 *[8]uint64 `json:"hashBlock512"`
	LenProcessed uint64     `json:"lenProcessed"`
	TempBlock512 *[128]byte `json:"tempBlock512"`
}

// Structure personalized for sha384
type sha384 struct {
	hasher512 `json:"hasher384"`
}

// Structure personalized for sha512
type sha512 struct {
	hasher512 `json:"hasher512"`
}

// Structure personalized for sha512t224
type sha512t224 struct {
	hasher512 `json:"hasher512t224"`
}

// Structure personalized for sha512t256
type sha512t256 struct {
	hasher512 `json:"hasher512t256"`
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

// Copy returns a deep copy
func (hasher *sha384) Copy() Hasher {
	return hasherCopy(New(Sha384), hasher)
}

// Copy returns a deep copy
func (hasher *sha512) Copy() Hasher {
	return hasherCopy(New(Sha512), hasher)
}

// Copy returns a deep copy
func (hasher *sha512t224) Copy() Hasher {
	return hasherCopy(New(Sha512t224), hasher)
}

// Copy returns a deep copy
func (hasher *sha512t256) Copy() Hasher {
	return hasherCopy(New(Sha512t256), hasher)
}

// HashAlgorithm returns the hash algorithm of the "object"
func (hasher *sha384) HashAlgorithm() HashAlgorithm {
	return Sha384
}

// HashAlgorithm returns the hash algorithm of the "object"
func (hasher *sha512) HashAlgorithm() HashAlgorithm {
	return Sha512
}

// HashAlgorithm returns the hash algorithm of the "object"
func (hasher *sha512t224) HashAlgorithm() HashAlgorithm {
	return Sha512t224
}

// HashAlgorithm returns the hash algorithm of the "object"
func (hasher *sha512t256) HashAlgorithm() HashAlgorithm {
	return Sha512t256
}

// InterimSum returns "the sum so far" without finalizing the original hasher
func (hasher sha384) InterimSum() interface{} {
	return hasher.Copy().Sum()

}

// InterimSum returns "the sum so far" without finalizing the original hasher
func (hasher sha512) InterimSum() interface{} {
	return hasher.Copy().Sum()

}

// InterimSum returns "the sum so far" without finalizing the original hasher
func (hasher sha512t224) InterimSum() interface{} {
	return hasher.Copy().Sum()
}

// InterimSum returns "the sum so far" without finalizing the original hasher
func (hasher sha512t256) InterimSum() interface{} {
	return hasher.Copy().Sum()
}

// Sum returns the final sum and marks the hasher as finished to prevent additional writes
func (hasher *sha384) Sum() interface{} {
	if !hasher.Finished {
		finalize512(&hasher.hasher512)
	}
	hasher.Finished = true
	var digest [48]byte
	for index := 0; index < 48; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.HashBlock512[index/8])
	}
	return digest
}

// Sum returns the final sum and marks the hasher as finished to prevent additional writes
func (hasher *sha512) Sum() interface{} {
	if !hasher.Finished {
		finalize512(&hasher.hasher512)
	}
	hasher.Finished = true
	var digest [64]byte
	for index := 0; index < 64; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.HashBlock512[index/8])
	}
	return digest
}

// Sum returns the final sum and marks the hasher as finished to prevent additional writes
func (hasher *sha512t224) Sum() interface{} {
	if !hasher.Finished {
		finalize512(&hasher.hasher512)
	}
	hasher.Finished = true
	var digest [28]byte
	for index := 0; index < 24; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.HashBlock512[index/8])
	}
	binary.BigEndian.PutUint32(digest[24:28], uint32(hasher.HashBlock512[3]>>32)) // Pesky left-over
	return digest
}

// Sum returns the final sum and marks the hasher as finished to prevent additional writes
func (hasher *sha512t256) Sum() interface{} {
	if !hasher.Finished {
		finalize512(&hasher.hasher512)
	}
	hasher.Finished = true
	var digest [32]byte
	for index := 0; index < 32; index += 8 {
		binary.BigEndian.PutUint64(digest[index:index+8], hasher.HashBlock512[index/8])
	}
	return digest
}

// Write pushes additional data into the hasher; can be called multiple times in streaming applications
func (hasher *sha384) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

// Write pushes additional data into the hasher; can be called multiple times in streaming applications
func (hasher *sha512) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

// Write pushes additional data into the hasher; can be called multiple times in streaming applications
func (hasher *sha512t224) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

// Write pushes additional data into the hasher; can be called multiple times in streaming applications
func (hasher *sha512t256) Write(message []byte) Hasher {
	write512(&hasher.hasher512, message)
	return hasher
}

// init creates an initialized structure specific to the algorithm in play
func (hasher *sha384) init(hashAlgorithm HashAlgorithm) Hasher {
	hasher.LenProcessed = 0
	hasher.TempBlock512 = &[128]byte{0}
	hasher.HashBlock512 = &[8]uint64{ // The specific/unique initial conditions for SHA-384 H[0:7]
		0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
		0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
	}
	return hasher
}

// init creates an initialized structure specific to the algorithm in play
func (hasher *sha512) init(hashAlgorithm HashAlgorithm) Hasher {
	hasher.LenProcessed = 0
	hasher.TempBlock512 = &[128]byte{0}
	hasher.HashBlock512 = &[8]uint64{ // The specific/unique initial conditions for SHA-512 H[0:7]
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	return hasher
}

// init creates an initialized structure specific to the algorithm in play
func (hasher *sha512t224) init(hashAlgorithm HashAlgorithm) Hasher {
	hasher.LenProcessed = 0
	hasher.TempBlock512 = &[128]byte{0}
	hasher.HashBlock512 = &[8]uint64{ // The specific/unique initial conditions for SHA-512t224 H[0:7]
		0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
		0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
	}
	return hasher
}

// init creates an initialized structure specific to the algorithm in play
func (hasher *sha512t256) init(hashAlgorithm HashAlgorithm) Hasher {
	hasher.LenProcessed = 0
	hasher.TempBlock512 = &[128]byte{0}
	hasher.HashBlock512 = &[8]uint64{ // The specific/unique initial conditions for SHA-512t256 H[0:7]
		0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
		0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
	}
	return hasher
}

// write512 does the real work of message ingestion
func write512(hasher *hasher512, message []byte) {
	if hasher.Finished {
		LogFatal("Cannot call Write() after Sum() because hasher has been finalized")
	}
	if hasher.LenProcessed+uint64(len(message)) < hasher.LenProcessed {
		LogFatal("Total message length of 2**64 has been exceeded")
	}

	// If message fits into non-empty tempBlock without filling it: append, adjust status and finish
	if len(message)+hasher.FillLine < bYTESINBLOCK512 {
		copy(hasher.TempBlock512[hasher.FillLine:hasher.FillLine+len(message)], message)
		hasher.LenProcessed += uint64(len(message))
		hasher.FillLine += len(message)
		return
	}

	// If message can fill non-empty tempBlock: append, hash it and call back with message remainder
	if hasher.FillLine > 0 && len(message)+hasher.FillLine > (bYTESINBLOCK512-1) {
		copy(hasher.TempBlock512[hasher.FillLine:hasher.FillLine+(bYTESINBLOCK512-hasher.FillLine)], message)
		hasher.LenProcessed += uint64(bYTESINBLOCK512 - hasher.FillLine)
		oneBlock512(hasher, hasher.TempBlock512[:])
		var tempFill = bYTESINBLOCK512 - hasher.FillLine
		hasher.FillLine = 0
		write512(hasher, message[tempFill:]) // One-off recursion
		return
	}

	// If empty tempBlock and message > block size: hash block-by-block
	var index int
	for (hasher.FillLine == 0) && (len(message)-index > (bYTESINBLOCK512 - 1)) {
		oneBlock512(hasher, message[index:index+bYTESINBLOCK512])
		index += bYTESINBLOCK512
		hasher.LenProcessed += uint64(bYTESINBLOCK512)
	}

	// If message segment remainder exists: call back
	if len(message)-index > 0 {
		write512(hasher, message[index:]) // One-off recursion
		return
	}
}

// finalize512 finishes the calculation by padding, marking length, and hashing final block(s)
func finalize512(hasher *hasher512) {
	// Finalize by hashing last block if padding will fit
	if hasher.FillLine < mAXBYTESINBLOCK512 {
		lastBlock512(hasher)
	}

	// Finalize by hashing two last blocks if padding will NOT fit
	if hasher.FillLine >= mAXBYTESINBLOCK512 && hasher.FillLine < bYTESINBLOCK512 {
		fillBlock512(hasher)
		oneBlock512(hasher, hasher.TempBlock512[:])
		hasher.FillLine = 0
		fillBlock512(hasher)
		hasher.TempBlock512[hasher.FillLine] = 0
		tagLength512(hasher)
		oneBlock512(hasher, hasher.TempBlock512[:])
	}

	// Clear working data
	hasher.FillLine = 0
	fillBlock512(hasher)
}

// fillBlock512 sets the message-end marker and zeros the remainder
func fillBlock512(hasher *hasher512) {
	hasher.TempBlock512[hasher.FillLine] = 128 // Set MSB
	for index := hasher.FillLine + 1; index < bYTESINBLOCK512; index++ {
		hasher.TempBlock512[index] = 0x00 // Clear MSB
	}
}

// tagLength512 put the length field into the message end
func tagLength512(hasher *hasher512) {
	hasher.LenProcessed *= 8
	binary.BigEndian.PutUint64(hasher.TempBlock512[mAXBYTESINBLOCK512+8:bYTESINBLOCK512], hasher.LenProcessed)
}

// lastBlock512 nearly done!
func lastBlock512(hasher *hasher512) {
	fillBlock512(hasher)
	tagLength512(hasher)
	oneBlock512(hasher, hasher.TempBlock512[:])
}

// Message schedule (faster out here)
var w512 [80]uint64

// oneBlock256 does one full hash block iteration
func oneBlock512(hasher *hasher512, message []byte) {
	// First 16 w512 are straightforward
	for i := 0; i < 16; i++ {
		j := i * 8
		w512[i] = binary.BigEndian.Uint64(message[j : j+8])
	}

	// Remaining 64 w512 a little more complicated
	for i := 16; i < 80; i = i + 4 {
		t1 := bits.RotateLeft64(w512[i-2], -19) ^ bits.RotateLeft64(w512[i-2], -61) ^ (w512[i-2] >> 6)
		t2 := bits.RotateLeft64(w512[i-15], -1) ^ bits.RotateLeft64(w512[i-15], -8) ^ (w512[i-15] >> 7)
		w512[i] = t1 + w512[i-7] + t2 + w512[i-16]

		t1a := bits.RotateLeft64(w512[i-1], -19) ^ bits.RotateLeft64(w512[i-1], -61) ^ (w512[i-1] >> 6)
		t2a := bits.RotateLeft64(w512[i-14], -1) ^ bits.RotateLeft64(w512[i-14], -8) ^ (w512[i-14] >> 7)
		w512[i+1] = t1a + w512[i-6] + t2a + w512[i-15]

		t1b := bits.RotateLeft64(w512[i], -19) ^ bits.RotateLeft64(w512[i], -61) ^ (w512[i] >> 6)
		t2b := bits.RotateLeft64(w512[i-13], -1) ^ bits.RotateLeft64(w512[i-13], -8) ^ (w512[i-13] >> 7)
		w512[i+2] = t1b + w512[i-5] + t2b + w512[i-14]

		t1c := bits.RotateLeft64(w512[i+1], -19) ^ bits.RotateLeft64(w512[i+1], -61) ^ (w512[i+1] >> 6)
		t2c := bits.RotateLeft64(w512[i-12], -1) ^ bits.RotateLeft64(w512[i-12], -8) ^ (w512[i-12] >> 7)
		w512[i+3] = t1c + w512[i-4] + t2c + w512[i-13]
	}

	// Initialize working variables
	var e1, e2, e3, e4, a1, a2, a3, a4 uint64
	var a, b, c, d, e, f, g, h = hasher.HashBlock512[0], hasher.HashBlock512[1], hasher.HashBlock512[2],
		hasher.HashBlock512[3], hasher.HashBlock512[4], hasher.HashBlock512[5], hasher.HashBlock512[6],
		hasher.HashBlock512[7]

	for i := 0; i < 80; i = i + 8 {
		t1 := h + (bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^
			bits.RotateLeft64(e, -41)) + ((e & f) ^ (^e & g)) + sha512Constants[i] + w512[i]
		t2 := (bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^
			bits.RotateLeft64(a, -39)) + ((a & b) ^ (a & c) ^ (b & c))
		e1 = d + t1
		a1 = t1 + t2

		t1 = g + (bits.RotateLeft64(e1, -14) ^ bits.RotateLeft64(e1, -18) ^
			bits.RotateLeft64(e1, -41)) + ((e1 & e) ^ (^e1 & f)) + sha512Constants[i+1] + w512[i+1]
		t2 = (bits.RotateLeft64(a1, -28) ^ bits.RotateLeft64(a1, -34) ^
			bits.RotateLeft64(a1, -39)) + ((a1 & a) ^ (a1 & b) ^ (a & b))
		e2 = c + t1
		a2 = t1 + t2

		t1 = f + (bits.RotateLeft64(e2, -14) ^ bits.RotateLeft64(e2, -18) ^
			bits.RotateLeft64(e2, -41)) + ((e2 & e1) ^ (^e2 & e)) + sha512Constants[i+2] + w512[i+2]
		t2 = (bits.RotateLeft64(a2, -28) ^ bits.RotateLeft64(a2, -34) ^
			bits.RotateLeft64(a2, -39)) + ((a2 & a1) ^ (a2 & a) ^ (a1 & a))
		e3 = b + t1
		a3 = t1 + t2

		t1 = e + (bits.RotateLeft64(e3, -14) ^ bits.RotateLeft64(e3, -18) ^
			bits.RotateLeft64(e3, -41)) + ((e3 & e2) ^ (^e3 & e1)) + sha512Constants[i+3] + w512[i+3]
		t2 = (bits.RotateLeft64(a3, -28) ^ bits.RotateLeft64(a3, -34) ^
			bits.RotateLeft64(a3, -39)) + ((a3 & a2) ^ (a3 & a1) ^ (a2 & a1))
		e4 = a + t1
		a4 = t1 + t2

		t1 = e1 + (bits.RotateLeft64(e4, -14) ^ bits.RotateLeft64(e4, -18) ^
			bits.RotateLeft64(e4, -41)) + ((e4 & e3) ^ (^e4 & e2)) + sha512Constants[i+4] + w512[i+4]
		t2 = (bits.RotateLeft64(a4, -28) ^ bits.RotateLeft64(a4, -34) ^
			bits.RotateLeft64(a4, -39)) + ((a4 & a3) ^ (a4 & a2) ^ (a3 & a2))
		h = a1 + t1
		d = t1 + t2

		t1 = e2 + (bits.RotateLeft64(h, -14) ^ bits.RotateLeft64(h, -18) ^
			bits.RotateLeft64(h, -41)) + ((h & e4) ^ (^h & e3)) + sha512Constants[i+5] + w512[i+5]
		t2 = (bits.RotateLeft64(d, -28) ^ bits.RotateLeft64(d, -34) ^
			bits.RotateLeft64(d, -39)) + ((d & a4) ^ (d & a3) ^ (a4 & a3))
		g = a2 + t1
		c = t1 + t2

		t1 = e3 + (bits.RotateLeft64(g, -14) ^ bits.RotateLeft64(g, -18) ^
			bits.RotateLeft64(g, -41)) + ((g & h) ^ (^g & e4)) + sha512Constants[i+6] + w512[i+6]
		t2 = (bits.RotateLeft64(c, -28) ^ bits.RotateLeft64(c, -34) ^
			bits.RotateLeft64(c, -39)) + ((c & d) ^ (c & a4) ^ (d & a4))
		f = a3 + t1
		b = t1 + t2

		t1 = e4 + (bits.RotateLeft64(f, -14) ^ bits.RotateLeft64(f, -18) ^
			bits.RotateLeft64(f, -41)) + ((f & g) ^ (^f & h)) + sha512Constants[i+7] + w512[i+7]
		t2 = (bits.RotateLeft64(b, -28) ^ bits.RotateLeft64(b, -34) ^
			bits.RotateLeft64(b, -39)) + ((b & c) ^ (b & d) ^ (c & d))
		e = a4 + t1
		a = t1 + t2
	}

	hasher.HashBlock512[0] += a
	hasher.HashBlock512[1] += b
	hasher.HashBlock512[2] += c
	hasher.HashBlock512[3] += d
	hasher.HashBlock512[4] += e
	hasher.HashBlock512[5] += f
	hasher.HashBlock512[6] += g
	hasher.HashBlock512[7] += h
}
