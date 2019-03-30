package hasher

import (
	"crypto/sha256"
	"fmt"
	"math/rand" // Repeatable is good!
	"runtime/debug"
	"testing"
)

func assertEquals(t *testing.T, expected interface{}, actual interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v, got %v", expected, actual))
		t.Log(string(debug.Stack()))
	}
}

func TestNew(t *testing.T) {
	var expected = Sha256
	var xx = New(expected)
	assertEquals(t, expected, xx.hashAlgorithm)
}

func TestNewInit(t *testing.T) {
	var expected = Sha256
	var xx = New().Init(expected)
	assertEquals(t, expected, xx.hashAlgorithm)
}

func TestSha256ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha256).Write([]byte(tt)).Sum()
		expected := sha256.Sum256([]byte(tt))
		assertEquals(t, expected, actual)
	}
}

func TestSha256ShortCombo(t *testing.T) {

	var a = "abc"
	var b = "def"

	actual := New().Init(Sha256).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha256.Sum256([]byte(a + b))
	assertEquals(t, expected, actual)

}

func TestSha256Random(t *testing.T) {

	for length := 4; length < 1000; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New().Init(Sha256).Write(message).Sum()
		expected := sha256.Sum256(message)
		assertEquals(t, expected, actual)
	}
}
