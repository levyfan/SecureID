package com.github.levyfan.secureid;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

public class PublicKey extends MCL.G1 implements ECPublicKey {

    public PublicKey() {
        super();
    }

    public PublicKey(ECPublicKeySpec spec) {
        super();
        if (!KeyUtil.BN254.getCurve().equals(spec.getParams().getCurve())) {
            throw new IllegalArgumentException("curve not supported");
        }
        ECPoint point = spec.getW();
        String str = String.join(" ",
                "1",
                point.getAffineX().toString(16),
                point.getAffineY().toString(16));
        setString(str, 16); // 1 <x> <y> ; affine coordinate
    }

    public byte[] blind(byte[] msg, MCL.Fr random) {
        try (MCL.G1 gin = new MCL.G1();
             MCL.G1 gout = new MCL.G1()) {
            gin.hashAndMapTo(msg);
            MCL.g1Mul(gout, MCL.basePoint, random);
            MCL.g1Add(gout, gin, gout); // IN + r * G
            return gout.serialize();
        }
    }

    public byte[] unblind(byte[] in, MCL.Fr random) {
        try (MCL.G1 gin = new MCL.G1();
             MCL.G1 gout = new MCL.G1()) {
            gin.deserialize(in);
            MCL.g1Mul(gout, this, random);
            MCL.g1Sub(gout, gin, gout); // IN - r * Q
            return gout.serialize();
        }
    }

    @Override
    public ECPoint getW() {
        String str = getString(16); // 1 <x> <y> ; affine coordinate
        if (str.equals("0")) {
            return ECPoint.POINT_INFINITY;
        }
        String[] xy = str.split(" ");
        return new ECPoint(
                new BigInteger(xy[1], 16),
                new BigInteger(xy[2], 16));
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public ECParameterSpec getParams() {
        return KeyUtil.BN254;
    }
}
