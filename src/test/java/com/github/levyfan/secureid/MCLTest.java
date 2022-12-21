package com.github.levyfan.secureid;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class MCLTest {

    private SecretKey sk;
    private PublicKey pk;

    @Before
    public void setUp() {
        sk = SecretKey.generate();
        pk = sk.publicKey();
    }

    @After
    public void tearDown() {
        sk.close();
        pk.close();
    }

    @Test
    public void testCompute() {
        byte[] msg = "hello world".getBytes();

        byte[] signed1 = sk.sign1(msg);

        MCL.Fr random = MCL.Fr.rand();
        byte[] blinded = pk.blind(msg, random);
        byte[] signed2 = sk.sign2(blinded);
        byte[] unblinded = pk.unblind(signed2, random);
        random.close();

        Assert.assertArrayEquals(signed1, unblinded);
    }

    @Test
    public void testSign1() {
        SecretKey key = new SecretKey();
        key.setInt(123456);
        byte[] msg = "hello world".getBytes();

        byte[] signed1 = key.sign1(msg);

        StringBuilder hex = new StringBuilder();
        for (byte i : signed1) {
            hex.append(String.format("%02x", i));
        }
        Assert.assertEquals("120a19ba42d66e3b07f9b1042ecc241658b98fbd0066ac3a98ec7cd55e487b15", hex.toString());
        key.close();
    }
}
