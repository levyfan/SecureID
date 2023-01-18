package SecureID

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/herumi/mcl/ffi/go/mcl"
	"math/big"
)

type CommonCurveParams struct {
	elliptic.CurveParams
	A *big.Int // the constant of the curve equation
}

func (curve *CommonCurveParams) IsOnCurve(x, y *big.Int) bool {
	k := NewPublicKey(x, y)
	return (*mcl.G1)(k).IsValid()
}

var BN254 = CommonCurveParams{
	CurveParams: elliptic.CurveParams{
		Name:    "BN254",
		BitSize: 254,
		P:       bigFromHex("2523648240000001BA344D80000000086121000000000013A700000000000013"),
		N:       bigFromHex("2523648240000001BA344D8000000007FF9F800000000010A10000000000000D"),
		B:       bigFromHex("0000000000000000000000000000000000000000000000000000000000000002"),
		Gx:      bigFromHex("2523648240000001BA344D80000000086121000000000013A700000000000012"),
		Gy:      bigFromHex("0000000000000000000000000000000000000000000000000000000000000001"),
	},
	A: bigFromHex("0000000000000000000000000000000000000000000000000000000000000000"),
}

var oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func MarshalPKIXPublicKey(pub *PublicKey) ([]byte, error) {
	paramBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	x, y := pub.XY()
	publicKeyBytes := elliptic.Marshal(&BN254, x, y)

	return asn1.Marshal(pkixPublicKey{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	})
}

func ParsePKIXPublicKey(derBytes []byte) (pub *PublicKey, err error) {
	var pki pkixPublicKey
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	if !pki.Algo.Algorithm.Equal(oid) {
		return nil, errors.New("x509: unknown public key algorithm")
	}

	x, y := elliptic.Unmarshal(&BN254, pki.BitString.RightAlign())
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	return NewPublicKey(x, y), nil
}

func MarshalPKCS8PrivateKey(key *SecretKey) ([]byte, error) {
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
	}
	x, y := key.PublicKey().XY()
	privateKey := make([]byte, (BN254.N.BitLen()+7)/8)

	buf, err := asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D().FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(&BN254, x, y)},
	})
	if err != nil {
		return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(pkcs8{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{FullBytes: oidBytes},
		},
		PrivateKey: buf,
	})
}

func ParsePKCS8PrivateKey(der []byte) (key *SecretKey, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	if !privKey.Algo.Algorithm.Equal(oid) {
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}

	var ecpk ecPrivateKey
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &ecpk); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if ecpk.Version != 1 {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.PrivateKey)
	}
	k := new(big.Int).SetBytes(ecpk.PrivateKey)
	return NewSecretKey(k), nil
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("internal error: invalid encoding")
	}
	return b
}
