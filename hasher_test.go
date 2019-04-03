package hasher

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/rand"
	"runtime/debug"
	"testing"
)

func assertEquals(t *testing.T, expected interface{}, actual interface{}, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v,\n    got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

/*
Examples for documentation
*/

func ExampleNew() {
	var instance = New()
	fmt.Println(instance.HashAlgorithm(), None)
	// Output: 0 0
}

func ExampleNew_sha256() {
	var instance = New(Sha256)
	fmt.Println(instance.HashAlgorithm(), Sha256)
	// Output: 2 2
}

func ExampleNew_sha512() {
	var instance = New(Sha512)
	fmt.Println(instance.HashAlgorithm(), Sha512)
	// Output: 4 4
}

func ExampleHasher_Init() {
	var instance = New()
	instance.Init(Sha256)
	fmt.Println(instance.HashAlgorithm(), Sha256)
	// Output: 2 2
}

func ExampleHasher_Init_fluent() {
	var instance = New().Init(Sha512)
	fmt.Println(instance.HashAlgorithm(), Sha512)
	// Output: 4 4
}

func ExampleHasher_HashAlgorithm() {
	var hashAlgorithm = New(Sha256).HashAlgorithm()
	fmt.Println(hashAlgorithm, Sha256)
	// Output: 2 2

}

func ExampleHasher_Write() {
	var instance = New(Sha256)
	instance.Write([]byte("a message"))
	fmt.Println(instance.Sum())
	// Output: [245 60 9 202 57 113 122 69 198 45 154 202 143 129 19 237 219 253 95 129 220 171 11 51 177 193 131 64 117 34 94 104]
}

func ExampleHasher_Write_fluent() {
	var instance = New(Sha256).Write([]byte("a message"))
	fmt.Println(instance.Sum())
	// Output: [245 60 9 202 57 113 122 69 198 45 154 202 143 129 19 237 219 253 95 129 220 171 11 51 177 193 131 64 117 34 94 104]
}

func ExampleHasher_Write_multiple() {
	var instance = New(Sha256).Write([]byte("a message")).Write([]byte("another optional segment"))
	instance.Write([]byte("this is good for streaming applications"))
	fmt.Println(instance.Sum())
	// Output: [122 247 122 79 222 228 168 188 61 59 32 213 122 246 247 145 34 166 192 225 110 145 228 59 99 53 78 100 55 117 214 124]
}

func ExampleHasher_Sum() {
	var instance = New(Sha256).Write([]byte("a message"))
	sum := instance.Sum()
	fmt.Println(sum)
	// Output: [245 60 9 202 57 113 122 69 198 45 154 202 143 129 19 237 219 253 95 129 220 171 11 51 177 193 131 64 117 34 94 104]
}

func ExampleHasher_Sum_fluent() {
	var sum = New(Sha256).Write([]byte("a message")).Write([]byte("another optional segment")).Sum()
	fmt.Println(sum)
	// Output: [252 16 58 203 75 29 177 225 67 41 16 151 176 98 11 131 31 119 53 170 216 249 212 142 119 85 1 15 140 208 80 29]
}

/*
Test the constructor and initialization
*/

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

func TestEmpty(t *testing.T) {
	var message []byte
	actual := New().Init(Sha256).Write(message).Sum()
	expected := sha256.Sum256(message)
	assertEquals(t, expected, actual, "")
}

/*
Test each hash algorithm with short single messages
*/

func TestSha256ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha256).Write([]byte(tt)).Sum()
		expected := sha256.Sum256([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", len(tt)))
	}
}

func TestSha224ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha224).Write([]byte(tt)).Sum()
		expected := sha256.Sum224([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", len(tt)))
	}
}

func TestSha512ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha512).Write([]byte(tt)).Sum()
		expected := sha512.Sum512([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", len(tt)))
	}
}

func TestSha384ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha384).Write([]byte(tt)).Sum()
		expected := sha512.Sum384([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", len(tt)))
	}
}

func TestSha512t224ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha512t224).Write([]byte(tt)).Sum()
		expected := sha512.Sum512_224([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", len(tt)))
	}
}

func TestSha512t256ShortSingles(t *testing.T) {

	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block and more and ...",
	}

	for _, tt := range testCases {
		actual := New().Init(Sha512t256).Write([]byte(tt)).Sum()
		expected := sha512.Sum512_256([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", len(tt)))
	}
}

/*
Test 256/512 hash algorithm with short combo messages (for streaming etc)
*/

func TestSha256ShortCombos(t *testing.T) {

	var a = "abc"
	var b = "def"

	actual := New().Init(Sha256).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha256.Sum256([]byte(a + b))
	assertEquals(t, expected, actual, "")

}

func TestSha512ShortCombos(t *testing.T) {

	var a = "abc"
	var b = "def"

	actual := New().Init(Sha512).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha512.Sum512([]byte(a + b))
	assertEquals(t, expected, actual, "")

}

/*
Test 256/512 hash algorithm with messages that span each step of multiple blocks
*/

func TestSha256MediumSingles(t *testing.T) {

	for length := 10; length < 550; length++ {
		message := make([]byte, length)
		rand.Read(message)
		inst := New().Init(Sha256)
		actual := inst.Write([]byte(message)).Sum()
		expected := sha256.Sum256([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha512MediumSingles(t *testing.T) {

	for length := 10; length < 550; length++ {
		message := make([]byte, length)
		rand.Read(message)
		inst := New().Init(Sha512)
		actual := inst.Write([]byte(message)).Sum()
		expected := sha512.Sum512([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

/*
Test 256/512 hash algorithm with messages of increasing length
*/

func TestSha256Random(t *testing.T) {

	for length := 4; length < 10000; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New().Init(Sha256).Write(message).Sum()
		expected := sha256.Sum256(message)
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha512Random(t *testing.T) {

	for length := 4; length < 10000; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New().Init(Sha512).Write(message).Sum()
		expected := sha512.Sum512(message)
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

/*
FUZZ EVERYTHING! 1M iterations takes on the order of 2 minutes. This also highlights the coolness of streaming writes.
*/

func TestFuzzEverything(t *testing.T) {

	for iterations := 0; iterations < 1000000; iterations++ {

		// 5 random message lengths
		var length1 = rand.Intn(500)
		var length2 = rand.Intn(500)
		var length3 = rand.Intn(5000)
		var length4 = rand.Intn(500)
		var length5 = rand.Intn(500)

		// Each message will have random content
		message1 := make([]byte, length1)
		rand.Read(message1)
		message2 := make([]byte, length2)
		rand.Read(message2)
		message3 := make([]byte, length3)
		rand.Read(message3)
		message4 := make([]byte, length4)
		rand.Read(message4)
		message5 := make([]byte, length5)
		rand.Read(message4)

		bigMsg := append(append(append(append(message1, message2...), message3...), message4...), message5...)

		// Sha256
		actual := New(Sha256).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected1 := sha256.Sum256(bigMsg)
		assertEquals(t, expected1, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha224
		actual = New(Sha224).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected2 := sha256.Sum224(bigMsg)
		assertEquals(t, expected2, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha512
		actual = New(Sha512).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected3 := sha512.Sum512(bigMsg)
		assertEquals(t, expected3, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha384
		actual = New(Sha384).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected4 := sha512.Sum384(bigMsg)
		assertEquals(t, expected4, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha512t224
		actual = New(Sha512t224).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected5 := sha512.Sum512_224(bigMsg)
		assertEquals(t, expected5, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha512t256
		actual = New(Sha512t256).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected6 := sha512.Sum512_256(bigMsg)
		assertEquals(t, expected6, actual, fmt.Sprintf("length=%v", len(bigMsg)))
	}
}

/*
Benchmark 256/512 hash algorithms with a random 1MB message. go test -bench=.
*/

var bMsg = []byte{0}

func init() {
	var bLen = 1000000
	bMsg = make([]byte, bLen)
	rand.Read(bMsg)

}

func BenchmarkHasherSha256(b *testing.B) {
	for n := 0; n < b.N; n++ {
		New(Sha256).Write(bMsg).Sum()
	}
}

func BenchmarkGolangSha256(b *testing.B) {
	for n := 0; n < b.N; n++ {
		sha256.Sum256(bMsg)
	}
}

func BenchmarkHasherSha512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		New(Sha512).Write(bMsg).Sum()
	}
}

func BenchmarkGolangSha512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		sha512.Sum512(bMsg)
	}
}
