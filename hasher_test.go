package hasher

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"runtime/debug"
	"testing"
)

func assertEquals(t *testing.T, expected interface{}, actual interface{}, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v, got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

func TestNew(t *testing.T) {
	var expected = Sha256
	var xx = New(expected)
	assertEquals(t, expected, xx.hashAlgorithm, "")
}

func TestNewInit(t *testing.T) {
	var expected = Sha256
	var xx = New().Init(expected)
	assertEquals(t, expected, xx.hashAlgorithm, "")
}

func TestSha256ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha256).Write([]byte(tt)).Sum()
		expected := sha256.Sum256([]byte(tt))
		assertEquals(t, expected, actual, "")
	}
}

func TestSha224ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha224).Write([]byte(tt)).Sum()
		expected := sha256.Sum224([]byte(tt))
		assertEquals(t, expected, actual, "")
	}
}

func TestSha256ShortCombo(t *testing.T) {

	var a = "abc"
	var b = "def"

	actual := New().Init(Sha256).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha256.Sum256([]byte(a + b))
	assertEquals(t, expected, actual, "")

}

func TestSha256MediumSingles(t *testing.T) {

	for length := 50; length < 268; length++ {
		message := make([]byte, length)
		rand.Read(message)
		inst := New().Init(Sha256)
		actual := inst.Write([]byte(message)).Sum()
		expected := sha256.Sum256([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha256Random(t *testing.T) {

	for length := 4; length < 10000; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New().Init(Sha256).Write(message).Sum()
		expected := sha256.Sum256(message)
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha256MegaCombos(t *testing.T) {

	for iterations := 0; iterations < 50000; iterations++ {
		var length1 = rand.Intn(300)
		var length2 = rand.Intn(300)
		var length3 = rand.Intn(300)
		var length4 = rand.Intn(300)

		message1 := make([]byte, length1)
		rand.Read(message1)
		message2 := make([]byte, length2)
		rand.Read(message2)
		message3 := make([]byte, length3)
		rand.Read(message3)
		message4 := make([]byte, length4)
		rand.Read(message4)

		actual := New(Sha256).Write(message1).Write(message2).Write(message3).Write(message4).Sum()
		bigMsg := append(append(append(message1, message2...), message3...), message4...)
		expected := sha256.Sum256(bigMsg)
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", len(bigMsg)))

	}

}
