package com.github.levyfan.secureid;

public class SecretKey extends MCL.Fr {

    public static SecretKey generate() {
        SecretKey sk = new SecretKey();
        sk.setByCSPRNG();
        return sk;
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
}
