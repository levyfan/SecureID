import unittest
import secure_id
import secure_id_util


class SecureIDTestCase(unittest.TestCase):

    def test_compute(self):
        sk = secure_id.generate()
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


class KeyUtilTestCase(unittest.TestCase):

    def test_private_key(self):
        sk = secure_id.generate()
        sk_der = sk.export_key(format="DER")
        sk1 = secure_id_util.import_key(sk_der, private=True)
        self.assertEqual(sk.get_string(16), sk1.get_string(16))

    def test_load_java_private_pem(self):
        pem = "-----BEGIN PRIVATE KEY-----\n" \
              "MIICAQIBADCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiAlI2SCQAAAAbo0\n" \
              "TYAAAAAIYSEAAAAAABOnAAAAAAAAEzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" \
              "AAAAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEQQQl\n" \
              "I2SCQAAAAbo0TYAAAAAIYSEAAAAAABOnAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAA\n" \
              "AAAAAAAAAAAAAAAAAAABAiAlI2SCQAAAAbo0TYAAAAAH/5+AAAAAABChAAAAAAAA\n" \
              "DQIBAQSCAQ0wggEJAgEBBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHi\n" \
              "QKCB4TCB3gIBATArBgcqhkjOPQEBAiAlI2SCQAAAAbo0TYAAAAAIYSEAAAAAABOn\n" \
              "AAAAAAAAEzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAA\n" \
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEQQQlI2SCQAAAAbo0TYAAAAAI\n" \
              "YSEAAAAAABOnAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB\n" \
              "AiAlI2SCQAAAAbo0TYAAAAAH/5+AAAAAABChAAAAAAAADQIBAQ==\n" \
              "-----END PRIVATE KEY-----"
        key = secure_id_util.import_key(pem, private=True)
        self.assertEqual(123456, key.d)

    def test_public_key(self):
        sk = secure_id.generate()
        pk = sk.public_key()
        pk_der = pk.export_key(format="DER")
        pk1 = secure_id_util.import_key(pk_der, private=False)
        self.assertEqual(pk.get_string(16), pk1.get_string(16))

    def test_read_java_public_pem(self):
        sk = secure_id.generate()
        sk.set_int(123456)
        pk = sk.public_key()
        pem = "-----BEGIN PUBLIC KEY-----\n" \
              "MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiAlI2SCQAAAAbo0TYAA\n" \
              "AAAIYSEAAAAAABOnAAAAAAAAEzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" \
              "AAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEQQQlI2SC\n" \
              "QAAAAbo0TYAAAAAIYSEAAAAAABOnAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAA\n" \
              "AAAAAAAAAAAAAAABAiAlI2SCQAAAAbo0TYAAAAAH/5+AAAAAABChAAAAAAAADQIB\n" \
              "AQNCAAQPfbeED37nTLkeLzmHZmH4P4RFHNoSfSFnihasYJSK3xErzYqZeB5YEvOw\n" \
              "1C2a6svYAQd19smFtOdmdiMNoOvZ\n" \
              "-----END PUBLIC KEY-----"
        key = secure_id_util.import_key(pem, private=False)
        self.assertEqual(pk.get_string(16), key.get_string(16))


if __name__ == '__main__':
    unittest.main()
