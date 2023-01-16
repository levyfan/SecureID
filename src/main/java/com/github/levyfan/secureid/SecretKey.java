package com.github.levyfan.secureid;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;

public class SecretKey extends MCL.Fr implements ECPrivateKey {

    public static SecretKey generate() {
        SecretKey sk = new SecretKey();
        sk.setByCSPRNG();
        return sk;
    }

    public SecretKey() {
        super();
    }

    public SecretKey(ECPrivateKeySpec spec) {
        super();
        if (!KeyUtil.BN254.getCurve().equals(spec.getParams().getCurve())) {
            throw new IllegalArgumentException("curve not supported");
        }
        BigInteger s = spec.getS();
        String str = s.toString(16);
        setString(str, 16);
    }

    public PublicKey publicKey() {
        PublicKey pk = new PublicKey();
        MCL.g1Mul(pk, MCL.basePoint, this);
        return pk;
    }

    public byte[] sign1(byte[] msg) {
        try (MCL.G1 gin = new MCL.G1();
             MCL.G1 gout = new MCL.G1()) {
            gin.hashAndMapTo(msg);
            MCL.g1Mul(gout, gin, this);
            return gout.serialize();
        }
    }

    public byte[] sign2(byte[] in) {
        try (MCL.G1 gin = new MCL.G1();
             MCL.G1 gout = new MCL.G1()) {
            gin.deserialize(in);
            MCL.g1Mul(gout, gin, this);
            return gout.serialize();
        }
    }

    @Override
    public BigInteger getS() {
        String str = getString(16);
        return new BigInteger(str, 16);
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        try {
            return KeyUtil.encode(this);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public ECParameterSpec getParams() {
        return KeyUtil.BN254;
    }
}
