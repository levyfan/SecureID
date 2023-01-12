package com.github.levyfan.secureid;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

public class KeyUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            ECBCKF = KeyFactory.getInstance("EC", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new Error(e);
        }
    }

    private static final BigInteger P = new BigInteger("2523648240000001BA344D80000000086121000000000013A700000000000013", 16);
    private static final BigInteger GX = new BigInteger("2523648240000001BA344D80000000086121000000000013A700000000000012", 16);
    private static final BigInteger N = new BigInteger("2523648240000001BA344D8000000007FF9F800000000010A10000000000000D", 16);

    public static final ECParameterSpec BN254 = new ECParameterSpec(
            new EllipticCurve(new ECFieldFp(P), BigInteger.ZERO, BigInteger.TWO),
            new ECPoint(GX, BigInteger.ONE),
            N,
            1);

    private static final KeyFactory ECBCKF;

    public static byte[] encode(Key key) throws InvalidKeyException {
        return ECBCKF.translateKey(key).getEncoded();
    }

    public static PublicKey decodePublic(byte[] bytes) throws InvalidKeySpecException {
        ECPublicKey key = (ECPublicKey) ECBCKF.generatePublic(new X509EncodedKeySpec(bytes));
        return new PublicKey(new ECPublicKeySpec(key.getW(), key.getParams()));
    }

    public static SecretKey decodePrivate(byte[] bytes) throws InvalidKeySpecException {
        ECPrivateKey key = (ECPrivateKey) ECBCKF.generatePrivate(new PKCS8EncodedKeySpec(bytes));
        return new SecretKey(new ECPrivateKeySpec(key.getS(), key.getParams()));
    }
}
