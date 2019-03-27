package hasher

import (
	"crypto/sha256"
	"testing"
)

func TestNew(t *testing.T) {
	var xx = New(Sha256)
	if xx.hashAlgorithm != Sha256 {
		t.Error("Expected SHA_@%^, got ", xx.hashAlgorithm)
	}
}

func TestNew2(t *testing.T) {
	var xx = New().Init(Sha256)
	if xx.hashAlgorithm != Sha256 {
		t.Error("Expected SHA_@%^, got ", xx.hashAlgorithm)
	}
}

func TestSha256(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one",
		"01234567890123456789012345678901234567890123456789012345678901234567890123456789", //longer than one block
	}

	for _, tt := range testCases {
		actual := New().Init(Sha256).Write([]byte(tt)).Sum()
		expected := sha256.Sum256([]byte(tt))
		if actual != expected {
			t.Errorf("Sum(%v):\n  expected %X\n    actual %X", tt, expected, actual)
		}
	}
}
