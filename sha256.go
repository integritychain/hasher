package hasher

import (
	"encoding/binary"
	"log"
	"math/bits"
)

// Hash a single block; Could be given a properly sized message segment or a tempBlock
func (hasher *Hasher) oneBlock256(message []byte) *Hasher {
	if len(message) != bYTESINBLOCK256 {
		log.Fatal("oneBlock256 got an odd sized block.")
	}
	// Message schedule
	var w [64]uint32

	// First 16 are straightforward
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = binary.BigEndian.Uint32(message[j : j+4])
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
		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) +
			((e & f) ^ (^e & g)) + hasher.sha256Constants[i] + w[i] // h + (4.5) + ch(e,f,g) + k + w
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) +
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

func (hasher *Hasher) eightBlocks256(message []byte) *Hasher {
	if len(message) != bYTESINBLOCK256 {
		log.Fatal("eightBlocks256 got an odd sized block.")
	}
	// Message schedule
	var w [64]uint32

	// First 16 are straightforward
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = binary.BigEndian.Uint32(message[j : j+4])
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

	for i := 0; i < 64; i += 2 {

		// BLOCK 00000000
		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) +
			((e & f) ^ (^e & g)) + hasher.sha256Constants[i] + w[i] // h + (4.5) + ch(e,f,g) + k + w
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) +
			((a & b) ^ (a & c) ^ (b & c)) // (4.4) + Maj(a,b,c)
		h = g
		g = f
		f = e
		e = d + t1 //
		d = c
		c = b
		b = a
		a = t1 + t2 //

		// BLOCK 11111111
		t1 = h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) +
			((e & f) ^ (^e & g)) + hasher.sha256Constants[i+1] + w[i+1] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) +
			((a & b) ^ (a & c) ^ (b & c)) // (4.4) + Maj(a,b,c)
		h = g
		g = f
		f = e
		e = d + t1 //
		d = c
		c = b
		b = a
		a = t1 + t2 //

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
