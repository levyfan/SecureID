package SecureID

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"github.com/herumi/mcl/ffi/go/mcl"
	"testing"
)

func TestCompute(t *testing.T) {
	sk := GenerateKey()
	pk := sk.PublicKey()
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

func TestSerializePublicKey(t *testing.T) {
	sk := GenerateKey()
	pk := sk.PublicKey()
	buf, err := MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Error(err)
	}
	pk1, err := ParsePKIXPublicKey(buf)
	if err != nil {
		t.Error(err)
	}
	if (*mcl.G1)(pk).GetString(16) != (*mcl.G1)(pk1).GetString(16) {
		t.Error("result mismatch")
	}
}

func TestReadJavaPublicPEM(t *testing.T) {
	sk := new(SecretKey)
	(*mcl.Fr)(sk).SetInt64(123456)
	pk1 := sk.PublicKey()

	pemstr := "-----BEGIN PUBLIC KEY-----\n" +
		"MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiAlI2SCQAAAAbo0TYAA\n" +
		"AAAIYSEAAAAAABOnAAAAAAAAEzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"AAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEQQQlI2SC\n" +
		"QAAAAbo0TYAAAAAIYSEAAAAAABOnAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"AAAAAAAAAAAAAAABAiAlI2SCQAAAAbo0TYAAAAAH/5+AAAAAABChAAAAAAAADQIB\n" +
		"AQNCAAQPfbeED37nTLkeLzmHZmH4P4RFHNoSfSFnihasYJSK3xErzYqZeB5YEvOw\n" +
		"1C2a6svYAQd19smFtOdmdiMNoOvZ\n" +
		"-----END PUBLIC KEY-----"
	data, _ := pem.Decode([]byte(pemstr))
	key, err := ParsePKIXPublicKey(data.Bytes)
	if err != nil {
		t.Error(err)
		return
	}
	if (*mcl.G1)(pk1).GetString(16) != (*mcl.G1)(key).GetString(16) {
		t.Error("result mismatch")
	}
}

func TestSerializePrivateKey(t *testing.T) {
	sk := GenerateKey()
	buf, err := MarshalPKCS8PrivateKey(sk)
	if err != nil {
		t.Error(err)
	}
	sk1, err := ParsePKCS8PrivateKey(buf)
	if err != nil {
		t.Error(err)
	}
	if (*mcl.Fr)(sk).GetString(16) != (*mcl.Fr)(sk1).GetString(16) {
		t.Error("result mismatch")
	}
}

func TestReadJavaPrivatePEM(t *testing.T) {
	pemstr := "-----BEGIN PRIVATE KEY-----\n" +
		"MIICAQIBADCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiAlI2SCQAAAAbo0\n" +
		"TYAAAAAIYSEAAAAAABOnAAAAAAAAEzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"AAAAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEQQQl\n" +
		"I2SCQAAAAbo0TYAAAAAIYSEAAAAAABOnAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAA\n" +
		"AAAAAAAAAAAAAAAAAAABAiAlI2SCQAAAAbo0TYAAAAAH/5+AAAAAABChAAAAAAAA\n" +
		"DQIBAQSCAQ0wggEJAgEBBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHi\n" +
		"QKCB4TCB3gIBATArBgcqhkjOPQEBAiAlI2SCQAAAAbo0TYAAAAAIYSEAAAAAABOn\n" +
		"AAAAAAAAEzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAA\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEQQQlI2SCQAAAAbo0TYAAAAAI\n" +
		"YSEAAAAAABOnAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB\n" +
		"AiAlI2SCQAAAAbo0TYAAAAAH/5+AAAAAABChAAAAAAAADQIBAQ==\n" +
		"-----END PRIVATE KEY-----"
	data, _ := pem.Decode([]byte(pemstr))
	key, err := ParsePKCS8PrivateKey(data.Bytes)
	if err != nil {
		t.Error(err)
		return
	}
	if key.D().Int64() != 123456 {
		t.Error(key.D())
	}
}

func BenchmarkSign1(b *testing.B) {
	sk := GenerateKey()
	msg := []byte("hello world")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sk.Sign1(msg)
		if err != nil {
			b.Error(err)
		}
	}
}
