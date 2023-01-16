import re

from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import _expand_subject_public_key_info
from Crypto.PublicKey.ECC import _Curve, _curves, UnsupportedEccFeature, _import_rfc5915_der
from Crypto.Util.py3compat import tobytes, tostr, bord

from secure_id import SecretKey, PublicKey

# FIXME: a!=-3 is not supported in python crypto
bn254 = _Curve(Integer(0x2523648240000001BA344D80000000086121000000000013A700000000000013),  # p
               Integer(0x0000000000000000000000000000000000000000000000000000000000000002),  # b
               Integer(0x2523648240000001BA344D8000000007FF9F800000000010A10000000000000D),  # order
               Integer(0x2523648240000001BA344D80000000086121000000000013A700000000000012),  # Gx
               Integer(0x0000000000000000000000000000000000000000000000000000000000000001),  # Gy
               None,  # G
               254,  # modulus_bits
               "1.2.840.10045.2.1",  # oid
               None,  # context
               "BN254",  # desc
               None,  # openssh
               "bn254")
_curves["bn254"] = bn254


def _import_public_der(ec_point, curve_oid=None):
    curve = _curves["bn254"]
    modulus_bytes = curve.p.size_in_bytes()
    point_type = bord(ec_point[0])
    if point_type != 0x04:
        raise ValueError("Incorrect EC point encoding")
    if len(ec_point) != (1 + 2 * modulus_bytes):
        raise ValueError("Incorrect EC point length")
    x = Integer.from_bytes(ec_point[1:modulus_bytes + 1])
    y = Integer.from_bytes(ec_point[modulus_bytes + 1:])
    return PublicKey(point_x=x, point_y=y)


def _import_subjectPublicKeyInfo(encoded):
    oid, ec_point, params = _expand_subject_public_key_info(encoded)
    if oid != "1.2.840.10045.2.1":
        raise UnsupportedEccFeature("Unsupported ECC OID: %s" % oid)
    if not params:
        raise ValueError("Missing ECC parameters for ECC OID %s" % oid)
    # curve_oid = DerObjectId().decode(params).value
    curve_oid = oid
    return _import_public_der(ec_point, curve_oid=curve_oid)


def _import_pkcs8(encoded, passphrase):
    from Crypto.IO import PKCS8
    algo_oid, private_key, params = PKCS8.unwrap(encoded, passphrase)
    if algo_oid != "1.2.840.10045.2.1":
        raise UnsupportedEccFeature("Unsupported ECC purpose (OID: %s)" % algo_oid)
    # curve_oid = DerObjectId().decode(params).value
    curve_oid = algo_oid
    return _import_rfc5915_der(private_key, passphrase, curve_oid)


def import_key(encoded, private):
    encoded = tobytes(encoded)
    if encoded.startswith(b'-----'):  # PEM
        from Crypto.IO import PEM
        text_encoded = tostr(encoded)
        # Remove any EC PARAMETERS section
        # Ignore its content because the curve type must be already given in the key
        ecparams_start = "-----BEGIN EC PARAMETERS-----"
        ecparams_end = "-----END EC PARAMETERS-----"
        text_encoded = re.sub(ecparams_start + ".*?" + ecparams_end, "",
                              text_encoded,
                              flags=re.DOTALL)
        der_encoded, marker, enc_flag = PEM.decode(text_encoded, None)
    elif len(encoded) > 0 and bord(encoded[0]) == 0x30:  # DER
        der_encoded = encoded
    else:
        raise ValueError("ECC key format is not supported")
    if private:
        return SecretKey(d=_import_pkcs8(der_encoded, None).d)
    else:
        return _import_subjectPublicKeyInfo(der_encoded)
