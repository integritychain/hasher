package hasher

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
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
		"0123456789012345678901234567890123456789012345678901234567890",                    //just short of one block
	}

	for _, tt := range testCases {
		actual := New().Init(Sha256).Write([]byte(tt)).Sum()
		expected := sha256.Sum256([]byte(tt))
		if actual != expected {
			t.Errorf("Sum(%v):\n  expected %X\n    actual %X", tt, expected, actual)
		}
	}
}

func TestMoreSha256(t *testing.T) {
	for x := 0; x < 50; x++ {
		var length = rand.Intn(1000)
		var message [1000]byte
		for i := range message {
			message[i] = byte(rand.Int())
		}
		fmt.Println(length)
		actual := New().Init(Sha256).Write(message[:length]).Sum()
		expected := sha256.Sum256(message[:length])
		if actual != expected {
			t.Errorf("Sum(%v) %v:\n  expected %X\n    actual %X", length, message, expected, actual)
		}
	}
}
