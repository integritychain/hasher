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

	for i := 0; i < 64; i += 8 {

		// BLOCK 00000000
		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) +
			((e & f) ^ (^e & g)) + hasher.sha256Constants[i] + w[i] // h + (4.5) + ch(e,f,g) + k + w
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) +
			((a & b) ^ (a & c) ^ (b & c)) // (4.4) + Maj(a,b,c)
		h1 := g
		g1 := f
		f1 := e
		e1 := d + t1 //
		d1 := c
		c1 := b
		b1 := a
		a1 := t1 + t2 //

		// BLOCK 11111111
		t1 = h1 + (bits.RotateLeft32(e1, -6) ^ bits.RotateLeft32(e1, -11) ^ bits.RotateLeft32(e1, -25)) +
			((e1 & f1) ^ (^e1 & g1)) + hasher.sha256Constants[i+1] + w[i+1] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a1, -2) ^ bits.RotateLeft32(a1, -13) ^ bits.RotateLeft32(a1, -22)) +
			((a1 & b1) ^ (a1 & c1) ^ (b1 & c1)) // (4.4) + Maj(a,b,c)
		h2 := g1
		g2 := f1
		f2 := e1
		e2 := d1 + t1 //
		d2 := c1
		c2 := b1
		b2 := a1
		a2 := t1 + t2 //

		// BLOCK 22222222
		t1 = h2 + (bits.RotateLeft32(e2, -6) ^ bits.RotateLeft32(e2, -11) ^ bits.RotateLeft32(e2, -25)) +
			((e2 & f2) ^ (^e2 & g2)) + hasher.sha256Constants[i+2] + w[i+2] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a2, -2) ^ bits.RotateLeft32(a2, -13) ^ bits.RotateLeft32(a2, -22)) +
			((a2 & b2) ^ (a2 & c2) ^ (b2 & c2)) // (4.4) + Maj(a,b,c)
		h3 := g2
		g3 := f2
		f3 := e2
		e3 := d2 + t1 //
		d3 := c2
		c3 := b2
		b3 := a2
		a3 := t1 + t2 //

		// BLOCK 33333333
		t1 = h3 + (bits.RotateLeft32(e3, -6) ^ bits.RotateLeft32(e3, -11) ^ bits.RotateLeft32(e3, -25)) +
			((e3 & f3) ^ (^e3 & g3)) + hasher.sha256Constants[i+3] + w[i+3] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a3, -2) ^ bits.RotateLeft32(a3, -13) ^ bits.RotateLeft32(a3, -22)) +
			((a3 & b3) ^ (a3 & c3) ^ (b3 & c3)) // (4.4) + Maj(a,b,c)
		h4 := g3
		g4 := f3
		f4 := e3
		e4 := d3 + t1 //
		d4 := c3
		c4 := b3
		b4 := a3
		a4 := t1 + t2 //

		// BLOCK 44444444
		t1 = h4 + (bits.RotateLeft32(e4, -6) ^ bits.RotateLeft32(e4, -11) ^ bits.RotateLeft32(e4, -25)) +
			((e4 & f4) ^ (^e4 & g4)) + hasher.sha256Constants[i+4] + w[i+4] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a4, -2) ^ bits.RotateLeft32(a4, -13) ^ bits.RotateLeft32(a4, -22)) +
			((a4 & b4) ^ (a4 & c4) ^ (b4 & c4)) // (4.4) + Maj(a,b,c)
		h5 := g4
		g5 := f4
		f5 := e4
		e5 := d4 + t1 //
		d5 := c4
		c5 := b4
		b5 := a4
		a5 := t1 + t2 //

		// BLOCK 55555555
		t1 = h5 + (bits.RotateLeft32(e5, -6) ^ bits.RotateLeft32(e5, -11) ^ bits.RotateLeft32(e5, -25)) +
			((e5 & f5) ^ (^e5 & g5)) + hasher.sha256Constants[i+5] + w[i+5] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a5, -2) ^ bits.RotateLeft32(a5, -13) ^ bits.RotateLeft32(a5, -22)) +
			((a5 & b5) ^ (a5 & c5) ^ (b5 & c5)) // (4.4) + Maj(a,b,c)
		h6 := g5
		g6 := f5
		f6 := e5
		e6 := d5 + t1 //
		d6 := c5
		c6 := b5
		b6 := a5
		a6 := t1 + t2 //

		// BLOCK 66666666
		t1 = h6 + (bits.RotateLeft32(e6, -6) ^ bits.RotateLeft32(e6, -11) ^ bits.RotateLeft32(e6, -25)) +
			((e6 & f6) ^ (^e6 & g6)) + hasher.sha256Constants[i+6] + w[i+6] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a6, -2) ^ bits.RotateLeft32(a6, -13) ^ bits.RotateLeft32(a6, -22)) +
			((a6 & b6) ^ (a6 & c6) ^ (b6 & c6)) // (4.4) + Maj(a,b,c)
		h7 := g6
		g7 := f6
		f7 := e6
		e7 := d6 + t1 //
		d7 := c6
		c7 := b6
		b7 := a6
		a7 := t1 + t2 //

		// BLOCK 77777777
		t1 = h7 + (bits.RotateLeft32(e7, -6) ^ bits.RotateLeft32(e7, -11) ^ bits.RotateLeft32(e7, -25)) +
			((e7 & f7) ^ (^e7 & g7)) + hasher.sha256Constants[i+7] + w[i+7] // h + (4.5) + ch(e,f,g) + k + w
		t2 = (bits.RotateLeft32(a7, -2) ^ bits.RotateLeft32(a7, -13) ^ bits.RotateLeft32(a7, -22)) +
			((a7 & b7) ^ (a7 & c7) ^ (b7 & c7)) // (4.4) + Maj(a,b,c)
		h = g7
		g = f7
		f = e7
		e = d7 + t1 //
		d = c7
		c = b7
		b = a7
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
