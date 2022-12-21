import unittest
import secure_id


class SecureIDTestCase(unittest.TestCase):

    def test_compute(self):
        sk = secure_id.keygen()
        pk = sk.public_key()
        msg = b"hello world"

        signed1 = sk.sign1(msg)

        random = secure_id.rand()
        blinded = pk.blind(msg, random)
        signed2 = sk.sign2(blinded)
        unblinded = pk.unblind(signed2, random)

        self.assertEqual(signed1.raw, unblinded.raw)

    def test_sign1(self):
        sk = secure_id.SecretKey()
        sk.set_int(123456)
        msg = b"hello world"

        signed1 = sk.sign1(msg)
        self.assertEqual(signed1.raw.hex(), "120a19ba42d66e3b07f9b1042ecc241658b98fbd0066ac3a98ec7cd55e487b15")


if __name__ == '__main__':
    unittest.main()
