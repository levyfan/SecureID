package com.github.levyfan.secureid;

public class PublicKey extends MCL.G1 {

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
}
