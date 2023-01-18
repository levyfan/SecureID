package SecureID

import (
	"github.com/herumi/mcl/ffi/go/mcl"
	"math/big"
	"strings"
)

var basePoint *mcl.G1

func init() {
	if err := mcl.Init(mcl.CurveFp254BNb); err != nil {
		panic(err)
	}
	if err := mcl.SetMapToMode(0); err != nil {
		panic(err)
	}
	basePoint = new(mcl.G1)
	if err := basePoint.SetString("1 0x2523648240000001BA344D80000000086121000000000013A700000000000012 0x01", 16); err != nil {
		panic(err)
	}
}

type Key interface {
	Serialize() []byte
	Deserialize(buf []byte) error
}

type SecretKey mcl.Fr
type PublicKey mcl.G1

func NewSecretKey(d *big.Int) *SecretKey {
	str := d.Text(16)
	k := new(mcl.Fr)
	if err := k.SetString(str, 16); err != nil {
		panic("internal error: invalid encoding")
	}
	return (*SecretKey)(k)
}

func (sk *SecretKey) Sign1(msg []byte) ([]byte, error) {
	gin, gout := new(mcl.G1), new(mcl.G1)
	if err := gin.HashAndMapTo(msg); err != nil {
		return nil, err
	}
	mcl.G1Mul(gout, gin, (*mcl.Fr)(sk))
	return gout.Serialize(), nil
}

func (sk *SecretKey) Sign2(in []byte) ([]byte, error) {
	gin, gout := new(mcl.G1), new(mcl.G1)
	if err := gin.Deserialize(in); err != nil {
		return nil, err
	}
	mcl.G1Mul(gout, gin, (*mcl.Fr)(sk))
	return gout.Serialize(), nil
}

func (sk *SecretKey) PublicKey() *PublicKey {
	pk := new(mcl.G1)
	mcl.G1Mul(pk, basePoint, (*mcl.Fr)(sk))
	return (*PublicKey)(pk)
}

func (sk *SecretKey) D() *big.Int {
	str := (*mcl.Fr)(sk).GetString(16)
	return bigFromHex(str)
}

func NewPublicKey(x, y *big.Int) *PublicKey {
	str := strings.Join([]string{"1", x.Text(16), y.Text(16)}, " ")
	k := new(mcl.G1)
	if err := k.SetString(str, 16); err != nil {
		panic("internal error: invalid encoding")
	}
	return (*PublicKey)(k)
}

func (pk *PublicKey) Blind(msg []byte, random *mcl.Fr) ([]byte, error) {
	gin, gout := new(mcl.G1), new(mcl.G1)
	if err := gin.HashAndMapTo(msg); err != nil {
		return nil, err
	}
	mcl.G1Mul(gout, basePoint, random)
	mcl.G1Add(gout, gin, gout) // IN + r * G
	return gout.Serialize(), nil
}

func (pk *PublicKey) Unblind(in []byte, random *mcl.Fr) ([]byte, error) {
	gin, gout := new(mcl.G1), new(mcl.G1)
	if err := gin.Deserialize(in); err != nil {
		return nil, err
	}
	mcl.G1Mul(gout, (*mcl.G1)(pk), random)
	mcl.G1Sub(gout, gin, gout) // IN - r * Q
	return gout.Serialize(), nil
}

func (pk *PublicKey) XY() (*big.Int, *big.Int) {
	str := (*mcl.G1)(pk).GetString(16)
	if str == "0" {
		return big.NewInt(0), big.NewInt(0)
	}
	tokens := strings.Split(str, " ")
	return bigFromHex(tokens[1]), bigFromHex(tokens[2])
}

func GenerateKey() *SecretKey {
	sk := new(mcl.Fr)
	sk.SetByCSPRNG()
	return (*SecretKey)(sk)
}

func Rand() *mcl.Fr {
	random := new(mcl.Fr)
	random.SetByCSPRNG()
	return random
}
