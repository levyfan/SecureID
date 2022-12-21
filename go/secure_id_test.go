package SecureID

import (
	"bytes"
	"fmt"
	"github.com/herumi/mcl/ffi/go/mcl"
	"testing"
)

func TestCompute(t *testing.T) {
	sk, pk := Keygen()
	msg := []byte("hello world")

	signed1, err := sk.Sign1(msg)
	if err != nil {
		t.Error(err)
	}

	random := Rand()
	blinded, err := pk.Blind(msg, random)
	if err != nil {
		t.Error(err)
	}
	signed2, err := sk.Sign2(blinded)
	if err != nil {
		t.Error(err)
	}
	unblinded, err := pk.Unblind(signed2, random)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(signed1, unblinded) {
		t.Error("result mismatch")
	}
}

func TestSign1(t *testing.T) {
	sk := new(SecretKey)
	(*mcl.Fr)(sk).SetInt64(123456)
	msg := []byte("hello world")

	signed1, err := sk.Sign1(msg)
	if err != nil {
		t.Error(err)
	}
	hex := fmt.Sprintf("%x", signed1)
	if "120a19ba42d66e3b07f9b1042ecc241658b98fbd0066ac3a98ec7cd55e487b15" != hex {
		t.Error("result mismatch")
	}
}

func BenchmarkSign1(b *testing.B) {
	sk, _ := Keygen()
	msg := []byte("hello world")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sk.Sign1(msg)
		if err != nil {
			b.Error(err)
		}
	}
}
