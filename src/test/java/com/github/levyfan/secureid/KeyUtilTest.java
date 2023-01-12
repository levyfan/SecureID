package com.github.levyfan.secureid;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

public class KeyUtilTest {

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
    public void testSerializePublic() throws InvalidKeyException, InvalidKeySpecException {
        byte[] bytes = KeyUtil.encode(pk);
        try (PublicKey key = KeyUtil.decodePublic(bytes)) {
            Assert.assertArrayEquals(pk.serialize(), key.serialize());
        }
    }

    @Test
    public void testSerializePrivate() throws InvalidKeyException, InvalidKeySpecException {
        byte[] bytes = KeyUtil.encode(sk);
        try (SecretKey key = KeyUtil.decodePrivate(bytes)) {
            Assert.assertArrayEquals(sk.serialize(), key.serialize());
        }
    }
}
