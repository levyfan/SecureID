package SecureID

import "github.com/herumi/mcl/ffi/go/mcl"

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
	// TODO: add more key serialization format, eg ASN.1/PEM
}

type SecretKey mcl.Fr
type PublicKey mcl.G1

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

func Keygen() (*SecretKey, *PublicKey) {
	sk, pk := new(mcl.Fr), new(mcl.G1)
	sk.SetByCSPRNG()
	mcl.G1Mul(pk, basePoint, sk)
	return (*SecretKey)(sk), (*PublicKey)(pk)
}

func Rand() *mcl.Fr {
	random := new(mcl.Fr)
	random.SetByCSPRNG()
	return random
}
