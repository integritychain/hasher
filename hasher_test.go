package hasher

import (
	"crypto/sha256"
	"fmt"
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

func TestNew3(t *testing.T) {
	var msg = make([]byte, 64)
	str := "abc"
	for k, v := range []byte(str) {
		msg[k] = byte(v)
	}
	msg[3] = 128
	msg[63] = 24
	var xx = New().Init(Sha256).Write(msg).Sum()
	fmt.Printf("%X\n", xx)

	sum := sha256.Sum256([]byte("abc"))
	fmt.Printf("  %x\n", sum)

	t.Error("Got ", xx)

}
