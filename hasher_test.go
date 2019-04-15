package hasher_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	. "hasher"
	"math/rand" // Repeatable is good
	"reflect"
	"runtime/debug"
	"testing"
)

func assertEquals(t *testing.T, expected interface{}, actual interface{}, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v,\n    got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

//
// Documentation examples
//

func ExampleNew() {
	var instance1 = New(Sha224)
	var instance2 = New(Sha256)
	var instance3 = New(Sha384)
	var instance4 = New(Sha512)
	var instance5 = New(Sha512t224)
	var instance6 = New(Sha512t256)
	fmt.Printf("Types are %v %v %v %v %v %v", reflect.TypeOf(instance1), reflect.TypeOf(instance2),
		reflect.TypeOf(instance3), reflect.TypeOf(instance4), reflect.TypeOf(instance5),
		reflect.TypeOf(instance6))
	// Output: Types are *hasher.sha224 *hasher.sha256 *hasher.sha384 *hasher.sha512 *hasher.sha512t224 *hasher.sha512t256
}

func ExampleSha224_Copy() {
	var instance1 = New(Sha224).
		Write([]byte("Message goes here"))
	var instance2 = instance1.Copy()
	fmt.Printf("The sum for instance1 == instance2: %v", instance1.Sum() == instance2.Sum())
	// Output: The sum for instance1 == instance2: true
}

func ExampleSha256_Copy() {
	var instance1 = New(Sha256).
		Write([]byte("Message goes here"))
	var instance2 = instance1.Copy()
	fmt.Printf("The sum for instance1 == instance2: %v", instance1.Sum() == instance2.Sum())
	// Output: The sum for instance1 == instance2: true
}

func ExampleSha384_Copy() {
	var instance1 = New(Sha384).
		Write([]byte("Message goes here"))
	var instance2 = instance1.Copy()
	fmt.Printf("The sum for instance1 == instance2: %v", instance1.Sum() == instance2.Sum())
	// Output: The sum for instance1 == instance2: true
}

func ExampleSha512_Copy() {
	var instance1 = New(Sha512).
		Write([]byte("Message goes here"))
	var instance2 = instance1.Copy()
	fmt.Printf("The sum for instance1 == instance2: %v", instance1.Sum() == instance2.Sum())
	// Output: The sum for instance1 == instance2: true
}

func ExampleSha512t224_Copy() {
	var instance1 = New(Sha512t224).
		Write([]byte("Message goes here"))
	var instance2 = instance1.Copy()
	fmt.Printf("The sum for instance1 == instance2: %v", instance1.Sum() == instance2.Sum())
	// Output: The sum for instance1 == instance2: true
}

func ExampleSha512t256_Copy() {
	var instance1 = New(Sha512t256).
		Write([]byte("Message goes here"))
	var instance2 = instance1.Copy()
	fmt.Printf("The sum for instance1 == instance2: %v", instance1.Sum() == instance2.Sum())
	// Output: The sum for instance1 == instance2: true
}

func ExampleSha224_HashAlgorithm() {
	var instance = New(Sha224)
	fmt.Printf("Hash algorithm is (enumerated): %v", instance.HashAlgorithm())
	// Output: Hash algorithm is (enumerated): 1
}

func ExampleSha256_HashAlgorithm() {
	var instance = New(Sha256)
	fmt.Printf("Hash algorithm is (enumerated): %v", instance.HashAlgorithm())
	// Output: Hash algorithm is (enumerated): 2
}

func ExampleSha384_HashAlgorithm() {
	var instance = New(Sha384)
	fmt.Printf("Hash algorithm is (enumerated): %v", instance.HashAlgorithm())
	// Output: Hash algorithm is (enumerated): 3
}

func ExampleSha512_HashAlgorithm() {
	var instance = New(Sha512)
	fmt.Printf("Hash algorithm is (enumerated): %v", instance.HashAlgorithm())
	// Output: Hash algorithm is (enumerated): 4
}

func ExampleSha512t224_HashAlgorithm() {
	var instance = New(Sha512t224)
	fmt.Printf("Hash algorithm is (enumerated): %v", instance.HashAlgorithm())
	// Output: Hash algorithm is (enumerated): 5
}

func ExampleSha512t256_HashAlgorithm() {
	var instance = New(Sha512t256)
	fmt.Printf("Hash algorithm is (enumerated): %v", instance.HashAlgorithm())
	// Output: Hash algorithm is (enumerated): 6
}

func ExampleSha224_InterimSum() {
	var instance1 = New(Sha224).Write([]byte("Message goes here"))    // This one will be finalized
	var instance2 = New(Sha224).Write([]byte("Message goes here"))    // This one will have two segments
	fmt.Printf("Sum for instance1 == InterimSum for instance2: %v\n", // Sum/Interim should equal
		instance1.Sum() == instance2.InterimSum())
	instance2.Write([]byte(" - and another message segment here")) // Add another segment, then whole
	var instance3 = New(Sha224).Write([]byte("Message goes here - and another message segment here"))
	fmt.Printf("Final Sum for instance2 == Sum for instance3: %v", // Compare fragment vs whole
		instance2.Sum() == instance3.InterimSum())
	// Output: Sum for instance1 == InterimSum for instance2: true
	// Final Sum for instance2 == Sum for instance3: true
}

func ExampleSha256_InterimSum() {
	var instance1 = New(Sha256).Write([]byte("Message goes here"))    // This one will be finalized
	var instance2 = New(Sha256).Write([]byte("Message goes here"))    // This one will have two segments
	fmt.Printf("Sum for instance1 == InterimSum for instance2: %v\n", // Sum/Interim should equal
		instance1.Sum() == instance2.InterimSum())
	instance2.Write([]byte(" - and another message segment here")) // Add another segment, then whole
	var instance3 = New(Sha256).Write([]byte("Message goes here - and another message segment here"))
	fmt.Printf("Final Sum for instance2 == Sum for instance3: %v", // Compare fragment vs whole
		instance2.Sum() == instance3.InterimSum())
	// Output: Sum for instance1 == InterimSum for instance2: true
	// Final Sum for instance2 == Sum for instance3: true
}

func ExampleSha384_InterimSum() {
	var instance1 = New(Sha384).Write([]byte("Message goes here"))    // This one will be finalized
	var instance2 = New(Sha384).Write([]byte("Message goes here"))    // This one will have two segments
	fmt.Printf("Sum for instance1 == InterimSum for instance2: %v\n", // Sum/Interim should equal
		instance1.Sum() == instance2.InterimSum())
	instance2.Write([]byte(" - and another message segment here")) // Add another segment, then whole
	var instance3 = New(Sha384).Write([]byte("Message goes here - and another message segment here"))
	fmt.Printf("Final Sum for instance2 == Sum for instance3: %v", // Compare fragment vs whole
		instance2.Sum() == instance3.InterimSum())
	// Output: Sum for instance1 == InterimSum for instance2: true
	// Final Sum for instance2 == Sum for instance3: true
}

func ExampleSha512_InterimSum() {
	var instance1 = New(Sha512).Write([]byte("Message goes here"))    // This one will be finalized
	var instance2 = New(Sha512).Write([]byte("Message goes here"))    // This one will have two segments
	fmt.Printf("Sum for instance1 == InterimSum for instance2: %v\n", // Sum/Interim should equal
		instance1.Sum() == instance2.InterimSum())
	instance2.Write([]byte(" - and another message segment here")) // Add another segment, then whole
	var instance3 = New(Sha512).Write([]byte("Message goes here - and another message segment here"))
	fmt.Printf("Final Sum for instance2 == Sum for instance3: %v", // Compare fragment vs whole
		instance2.Sum() == instance3.InterimSum())
	// Output: Sum for instance1 == InterimSum for instance2: true
	// Final Sum for instance2 == Sum for instance3: true
}

func ExampleSha512t224_InterimSum() {
	var instance1 = New(Sha512t224).Write([]byte("Message goes here")) // This one will be finalized
	var instance2 = New(Sha512t224).Write([]byte("Message goes here")) // This one will have two segments
	fmt.Printf("Sum for instance1 == InterimSum for instance2: %v\n",  // Sum/Interim should equal
		instance1.Sum() == instance2.InterimSum())
	instance2.Write([]byte(" - and another message segment here")) // Add another segment, then whole
	var instance3 = New(Sha512t224).Write([]byte("Message goes here - and another message segment here"))
	fmt.Printf("Final Sum for instance2 == Sum for instance3: %v", // Compare fragment vs whole
		instance2.Sum() == instance3.InterimSum())
	// Output: Sum for instance1 == InterimSum for instance2: true
	// Final Sum for instance2 == Sum for instance3: true
}

func ExampleSha512t256_InterimSum() {
	var instance1 = New(Sha512t256).Write([]byte("Message goes here")) // This one will be finalized
	var instance2 = New(Sha512t256).Write([]byte("Message goes here")) // This one will have two segments
	fmt.Printf("Sum for instance1 == InterimSum for instance2: %v\n",  // Sum/Interim should equal
		instance1.Sum() == instance2.InterimSum())
	instance2.Write([]byte(" - and another message segment here")) // Add another segment, then whole
	var instance3 = New(Sha512t256).Write([]byte("Message goes here - and another message segment here"))
	fmt.Printf("Final Sum for instance2 == Sum for instance3: %v", // Compare fragment vs whole
		instance2.Sum() == instance3.InterimSum())
	// Output: Sum for instance1 == InterimSum for instance2: true
	// Final Sum for instance2 == Sum for instance3: true
}

func ExampleSha224_Sum() {
	var instance = New(Sha224).Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [117 160 150 92 3 235 194 97 207 145 106 35 43 150 26 27 56 132 215 253 150 169 130 54 134 8 116 86]
}

func ExampleSha256_Sum() {
	var instance = New(Sha256).Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [64 18 6 183 163 155 254 15 125 66 40 52 186 79 155 25 136 52 48 45 167 36 171 165 236 23 232 223 3 172 115 146]
}

func ExampleSha384_Sum() {
	var instance = New(Sha384).Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [168 165 209 227 136 115 182 42 209 89 107 85 189 125 115 141 189 26 131 136 127 233 83 41 161 10 39 159 199 80 149 45 186 163 100 168 83 66 4 45 116 78 215 29 195 239 255 124]
}

func ExampleSha512_Sum() {
	var instance = New(Sha512).Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [122 33 97 192 18 120 250 217 235 143 193 29 119 182 70 250 241 118 209 225 90 139 218 89 100 224 64 70 18 50 241 69 88 29 31 154 124 36 115 48 6 85 185 218 135 40 25 183 230 39 0 65 77 129 0 65 92 249 92 9 199 19 214 248]
}

func ExampleSha512t224_Sum() {
	var instance = New(Sha512t224).Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [246 135 58 240 202 39 27 63 125 131 74 123 115 0 122 31 244 207 161 43 23 1 91 180 196 192 175 84]
}

func ExampleSha512t256_Sum() {
	var instance = New(Sha512t256).Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [129 220 114 216 230 50 53 182 207 210 10 169 255 3 69 60 90 107 243 87 155 217 198 148 241 175 168 75 224 23 8 77]
}

func ExampleSha224_Write() {
	var instance = New(Sha224).
		Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [117 160 150 92 3 235 194 97 207 145 106 35 43 150 26 27 56 132 215 253 150 169 130 54 134 8 116 86]
}

func ExampleSha256_Write() {
	var instance = New(Sha256).
		Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [64 18 6 183 163 155 254 15 125 66 40 52 186 79 155 25 136 52 48 45 167 36 171 165 236 23 232 223 3 172 115 146]
}

func ExampleSha384_Write() {
	var instance = New(Sha384).
		Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [168 165 209 227 136 115 182 42 209 89 107 85 189 125 115 141 189 26 131 136 127 233 83 41 161 10 39 159 199 80 149 45 186 163 100 168 83 66 4 45 116 78 215 29 195 239 255 124]
}

func ExampleSha512_Write() {
	var instance = New(Sha512).
		Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [122 33 97 192 18 120 250 217 235 143 193 29 119 182 70 250 241 118 209 225 90 139 218 89 100 224 64 70 18 50 241 69 88 29 31 154 124 36 115 48 6 85 185 218 135 40 25 183 230 39 0 65 77 129 0 65 92 249 92 9 199 19 214 248]
}

func ExampleSha512t224_Write() {
	var instance = New(Sha512t224).
		Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [246 135 58 240 202 39 27 63 125 131 74 123 115 0 122 31 244 207 161 43 23 1 91 180 196 192 175 84]
}

func ExampleSha512t256_Write() {
	var instance = New(Sha512t256).
		Write([]byte("Message goes here"))
	fmt.Printf("Sum: %v", instance.Sum())
	// Output: Sum: [129 220 114 216 230 50 53 182 207 210 10 169 255 3 69 60 90 107 243 87 155 217 198 148 241 175 168 75 224 23 8 77]
}

//
// Functional tests
//

func TestSha224_Sum_ShortSingles(t *testing.T) {
	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block ...",
	}
	for _, tt := range testCases {
		actual := New(Sha224).
			Write([]byte(tt)).
			Sum()
		expected := sha256.Sum224([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("message=%v", tt))
	}
}

func TestSha256_Sum_ShortSingles(t *testing.T) {
	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block ...",
	}
	for _, tt := range testCases {
		actual := New(Sha256).
			Write([]byte(tt)).
			Sum()
		expected := sha256.Sum256([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("message=%v", tt))
	}
}

func TestSha384_Sum_ShortSingles(t *testing.T) {
	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block ...",
	}
	for _, tt := range testCases {
		actual := New(Sha384).
			Write([]byte(tt)).
			Sum()
		expected := sha512.Sum384([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("message=%v", tt))
	}
}

func TestSha512_Sum_ShortSingles(t *testing.T) {
	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block ...",
	}
	for _, tt := range testCases {
		actual := New(Sha512).
			Write([]byte(tt)).
			Sum()
		expected := sha512.Sum512([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("message=%v", tt))
	}
}

func TestSha512t224_Sum_ShortSingles(t *testing.T) {
	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block ...",
	}
	for _, tt := range testCases {
		actual := New(Sha512t224).
			Write([]byte(tt)).
			Sum()
		expected := sha512.Sum512_224([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("message=%v", tt))
	}
}

func TestSha512t256_Sum_ShortSingles(t *testing.T) {
	var testCases = []string{
		"abc", "hello there", "a little longer this time", "this is still within one block ...",
	}
	for _, tt := range testCases {
		actual := New(Sha512t256).
			Write([]byte(tt)).
			Sum()
		expected := sha512.Sum512_256([]byte(tt))
		assertEquals(t, expected, actual, fmt.Sprintf("message=%v", tt))
	}
}

func TestSha224_Sum_ShortCombos(t *testing.T) {
	var a, b = "abc", "def"
	actual := New(Sha224).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha256.Sum224([]byte(a + b))
	assertEquals(t, expected, actual, a+b)
}

func TestSha256_Sum_ShortCombos(t *testing.T) {
	var a, b = "abc", "def"
	actual := New(Sha256).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha256.Sum256([]byte(a + b))
	assertEquals(t, expected, actual, a+b)
}

func TestSha384_Sum_ShortCombos(t *testing.T) {
	var a, b = "abc", "def"
	actual := New(Sha384).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha512.Sum384([]byte(a + b))
	assertEquals(t, expected, actual, a+b)
}

func TestSha512_Sum_ShortCombos(t *testing.T) {
	var a, b = "abc", "def"
	actual := New(Sha512).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha512.Sum512([]byte(a + b))
	assertEquals(t, expected, actual, a+b)
}

func TestSha512t224_Sum_ShortCombos(t *testing.T) {
	var a, b = "abc", "def"
	actual := New(Sha512t224).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha512.Sum512_224([]byte(a + b))
	assertEquals(t, expected, actual, a+b)
}

func TestSha512t256_Sum_ShortCombos(t *testing.T) {
	var a, b = "abc", "def"
	actual := New(Sha512t256).Write([]byte(a)).Write([]byte(b)).Sum()
	expected := sha512.Sum512_256([]byte(a + b))
	assertEquals(t, expected, actual, a+b)
}

func TestSha224_Sum_Medium_Singles(t *testing.T) {
	for length := 40; length < 340; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New(Sha224).Write([]byte(message)).Sum()
		expected := sha256.Sum224([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha256_Sum_Medium_Singles(t *testing.T) {
	for length := 40; length < 340; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New(Sha256).Write([]byte(message)).Sum()
		expected := sha256.Sum256([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha384_Sum_Medium_Singles(t *testing.T) {
	for length := 40; length < 340; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New(Sha384).Write([]byte(message)).Sum()
		expected := sha512.Sum384([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha512_Sum_Medium_Singles(t *testing.T) {
	for length := 40; length < 340; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New(Sha512).Write([]byte(message)).Sum()
		expected := sha512.Sum512([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha512t224_Sum_Medium_Singles(t *testing.T) {
	for length := 40; length < 340; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New(Sha512t224).Write([]byte(message)).Sum()
		expected := sha512.Sum512_224([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha512t256_Sum_Medium_Singles(t *testing.T) {
	for length := 40; length < 340; length++ {
		message := make([]byte, length)
		rand.Read(message)
		actual := New(Sha512t256).Write([]byte(message)).Sum()
		expected := sha512.Sum512_256([]byte(message))
		assertEquals(t, expected, actual, fmt.Sprintf("length=%v", length))
	}
}

func TestSha224_Sum_Medium_Combos(t *testing.T) {
	for length1 := 40; length1 < 340; length1 = length1 + 4 {
		for length2 := 40; length2 < 120; length2 = length2 + 4 {
			message1 := make([]byte, length1)
			rand.Read(message1)
			message2 := make([]byte, length2)
			rand.Read(message2)
			actual := New(Sha224).Write([]byte(message1)).Write(message2).Sum()
			expected := sha256.Sum224([]byte((append(message1, message2...))))
			assertEquals(t, expected, actual, fmt.Sprintf("length=%v / %v", length1, length2))
		}
	}
}

func TestSha256_Sum_Medium_Combos(t *testing.T) {
	for length1 := 40; length1 < 340; length1 = length1 + 4 {
		for length2 := 40; length2 < 120; length2 = length2 + 4 {
			message1 := make([]byte, length1)
			rand.Read(message1)
			message2 := make([]byte, length2)
			rand.Read(message2)
			actual := New(Sha256).Write([]byte(message1)).Write(message2).Sum()
			expected := sha256.Sum256([]byte((append(message1, message2...))))
			assertEquals(t, expected, actual, fmt.Sprintf("length=%v / %v", length1, length2))
		}
	}
}

func TestSha384_Sum_Medium_Combos(t *testing.T) {
	for length1 := 40; length1 < 340; length1 = length1 + 4 {
		for length2 := 40; length2 < 120; length2 = length2 + 4 {
			message1 := make([]byte, length1)
			rand.Read(message1)
			message2 := make([]byte, length2)
			rand.Read(message2)
			actual := New(Sha384).Write([]byte(message1)).Write(message2).Sum()
			expected := sha512.Sum384([]byte((append(message1, message2...))))
			assertEquals(t, expected, actual, fmt.Sprintf("length=%v / %v", length1, length2))
		}
	}
}

func TestSha512_Sum_Medium_Combos(t *testing.T) {
	for length1 := 40; length1 < 340; length1 = length1 + 4 {
		for length2 := 40; length2 < 120; length2 = length2 + 4 {
			message1 := make([]byte, length1)
			rand.Read(message1)
			message2 := make([]byte, length2)
			rand.Read(message2)
			actual := New(Sha512).Write([]byte(message1)).Write(message2).Sum()
			expected := sha512.Sum512([]byte((append(message1, message2...))))
			assertEquals(t, expected, actual, fmt.Sprintf("length=%v / %v", length1, length2))
		}
	}
}

func TestSha512t224_Sum_Medium_Combos(t *testing.T) {
	for length1 := 40; length1 < 340; length1 = length1 + 4 {
		for length2 := 40; length2 < 120; length2 = length2 + 4 {
			message1 := make([]byte, length1)
			rand.Read(message1)
			message2 := make([]byte, length2)
			rand.Read(message2)
			actual := New(Sha512t224).Write([]byte(message1)).Write(message2).Sum()
			expected := sha512.Sum512_224([]byte((append(message1, message2...))))
			assertEquals(t, expected, actual, fmt.Sprintf("length=%v / %v", length1, length2))
		}
	}
}

func TestSha512t256_Sum_Medium_Combos(t *testing.T) {
	for length1 := 40; length1 < 340; length1 = length1 + 4 {
		for length2 := 40; length2 < 120; length2 = length2 + 4 {
			message1 := make([]byte, length1)
			rand.Read(message1)
			message2 := make([]byte, length2)
			rand.Read(message2)
			actual := New(Sha512t256).Write([]byte(message1)).Write(message2).Sum()
			expected := sha512.Sum512_256([]byte((append(message1, message2...))))
			assertEquals(t, expected, actual, fmt.Sprintf("length=%v / %v", length1, length2))
		}
	}
}

func TestFuzzEverything(t *testing.T) {

	for iterations := 0; iterations < 10000; iterations++ {

		// 5 random message lengths
		var length1 = rand.Intn(500)
		var length2 = rand.Intn(200)
		var length3 = rand.Intn(5000)
		var length4 = rand.Intn(100)
		var length5 = rand.Intn(1000)

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

		// Sha224
		actual := New(Sha224).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected2 := sha256.Sum224(bigMsg)
		assertEquals(t, expected2, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha256
		actual = New(Sha256).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected1 := sha256.Sum256(bigMsg)
		assertEquals(t, expected1, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha384
		actual = New(Sha384).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected4 := sha512.Sum384(bigMsg)
		assertEquals(t, expected4, actual, fmt.Sprintf("length=%v", len(bigMsg)))

		// Sha512
		actual = New(Sha512).Write(message1).Write(message2).Write(message3).Write(message4).Write(message5).Sum()
		expected3 := sha512.Sum512(bigMsg)
		assertEquals(t, expected3, actual, fmt.Sprintf("length=%v", len(bigMsg)))

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

var hitThis bool

func hitIt(_ ...interface{}) { hitThis = true }

func TestBadAlgorithmNone(t *testing.T) {
	LogFatal = hitIt
	hitThis = false
	var instance = New(None) // Bad hash algorithm
	assertEquals(t, true, hitThis, fmt.Sprintf("LogFatal did not hitIt: %v", instance))
}

func TestBadAlgorithm99(t *testing.T) {
	LogFatal = hitIt
	hitThis = false
	var instance = New(99) // Bad hash algorithm
	assertEquals(t, true, hitThis, fmt.Sprintf("LogFatal did not hitIt: %v", instance))
}

func TestBadWriteAfterSum256(t *testing.T) {
	LogFatal = hitIt
	hitThis = false
	var instance = New(Sha256).Write([]byte("message"))
	var sum = instance.Sum()
	instance.Write([]byte("this cannot be good"))
	assertEquals(t, true, hitThis, fmt.Sprintf("LogFatal did not hitIt: %v", sum))
}

func TestBadWriteAfterSum512(t *testing.T) {
	LogFatal = hitIt
	hitThis = false
	var instance = New(Sha512).Write([]byte("message"))
	var sum = instance.Sum()
	instance.Write([]byte("this cannot be good"))
	assertEquals(t, true, hitThis, fmt.Sprintf("LogFatal did not hitIt: %v", sum))
}

var bMsg = []byte{0}

func init() {
	var bLen = 8192
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
