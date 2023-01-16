from ctypes import Structure
from ctypes import byref
from ctypes import c_uint64
from ctypes import cdll
from ctypes import create_string_buffer
from ctypes.util import find_library


mclBn_CurveFp254BNb = 0
MCLBN_FP_UNIT_SIZE = 4
MCLBN_FR_UNIT_SIZE = 4
MCLBN_COMPILED_TIME_VAR = MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE
MCL_MAP_TO_MODE_ORIGINAL = 0

libmcl = cdll.LoadLibrary(find_library("mclbn256"))
if libmcl.mclBn_init(mclBn_CurveFp254BNb, MCLBN_COMPILED_TIME_VAR) != 0:
    raise ValueError("ERR mclBn_init curve", mclBn_CurveFp254BNb)
if libmcl.mclBn_setMapToMode(MCL_MAP_TO_MODE_ORIGINAL) != 0:
    raise ValueError("SetMapToMode mode", MCL_MAP_TO_MODE_ORIGINAL)


class BnFp(Structure):
    _fields_ = [("_d", c_uint64 * MCLBN_FP_UNIT_SIZE)]


class BnFr(Structure):
    _fields_ = [("_d", c_uint64 * MCLBN_FP_UNIT_SIZE)]

    def set_by_csprng(self):
        err = libmcl.mclBnFr_setByCSPRNG(byref(self))
        if err != 0:
            raise ValueError("err mclBnFr_setByCSPRNG")

    def set_int(self, x: int):
        libmcl.mclBnFr_setInt32(byref(self), x)

    def set_string(self, s: bytes, base: int):
        err = libmcl.mclBnFr_setStr(byref(self), s, len(s), base)
        if err != 0:
            raise ValueError("err mclBnFr_setStr", err)

    def get_string(self, base: int):
        buf = create_string_buffer(2048)
        n = libmcl.mclBnFr_getStr(byref(buf), len(buf), byref(self), base)
        if n == 0:
            raise ValueError("err mclBnFr_getStr")
        return buf[:n]

    def serialize(self):
        buf = create_string_buffer(libmcl.mclBn_getFrByteSize())
        n = libmcl.mclBnFr_serialize(byref(buf), len(buf), byref(self))
        if n == 0:
            raise ValueError("err mclBnFr_serialize")
        return buf

    def deserialize(self, buf: bytes):
        n = libmcl.mclBnFr_deserialize(byref(self), buf, len(buf))
        if n == 0 or int(n) != len(buf):
            raise ValueError("err mclBnFr_deserialize", buf)


class BnG1(Structure):
    _fields_ = [("_x", BnFp),
                ("_y", BnFp),
                ("_z", BnFp)]

    def set_string(self, s: bytes, base: int):
        err = libmcl.mclBnG1_setStr(byref(self), s, len(s), base)
        if err != 0:
            raise ValueError("err mclBnG1_setStr", err)

    def get_string(self, base: int):
        buf = create_string_buffer(2048)
        n = libmcl.mclBnG1_getStr(byref(buf), len(buf), byref(self), base)
        if n == 0:
            raise ValueError("err mclBnG1_getStr")
        return buf[:n]

    def hash_and_map_to(self, buf: bytes):
        err = libmcl.mclBnG1_hashAndMapTo(byref(self), buf, len(buf))
        if err != 0:
            raise ValueError("err mclBnG1_hashAndMapTo", err)

    def serialize(self):
        buf = create_string_buffer(libmcl.mclBn_getG1ByteSize())
        n = libmcl.mclBnG1_serialize(byref(buf), len(buf), byref(self))
        if n == 0:
            raise ValueError("err mclBnG1_serialize")
        return buf

    def deserialize(self, buf: bytes):
        n = libmcl.mclBnG1_deserialize(byref(self), buf, len(buf))
        if n == 0 or int(n) != len(buf):
            raise ValueError("err mclBnG1_deserialize", buf)


def g1mul(out: BnG1, x: BnG1, y: BnFr):
    libmcl.mclBnG1_mul(byref(out), byref(x), byref(y))


def g1add(out: BnG1, x: BnG1, y: BnG1):
    libmcl.mclBnG1_add(byref(out), byref(x), byref(y))


def g1sub(out: BnG1, x: BnG1, y: BnG1):
    libmcl.mclBnG1_sub(byref(out), byref(x), byref(y))


basePoint = BnG1()
basePoint.set_string(b"1 0x2523648240000001BA344D80000000086121000000000013A700000000000012 0x01", 16)


class SecretKey(BnFr):

    def __init__(self, d=None):
        super().__init__()
        if d is not None:
            s = bytes(hex(d), "utf-8")
            self.set_string(s, 16)

    def sign1(self, msg: bytes):
        gin, gout = BnG1(), BnG1()
        gin.hash_and_map_to(msg)
        g1mul(gout, gin, self)
        return gout.serialize()

    def sign2(self, _in: bytes):
        gin, gout = BnG1(), BnG1()
        gin.deserialize(_in)
        g1mul(gout, gin, self)
        return gout.serialize()

    def public_key(self):
        pk = PublicKey()
        g1mul(pk, basePoint, self)
        return pk

    @property
    def d(self):
        return int(self.get_string(16), 16)

    def export_key(self, **kwargs):
        from Crypto.PublicKey.ECC import EccKey
        key = EccKey(curve="bn254", d=self.d, point=self.public_key())
        return key.export_key(**kwargs)


class PublicKey(BnG1):

    def __init__(self, point_x=None, point_y=None):
        super().__init__()
        if point_x is not None and point_y is not None:
            s = " ".join(["1", hex(point_x), hex(point_y)])
            self.set_string(bytes(s, "utf-8"), 16)

    def blind(self, msg: bytes, random: BnFr):
        gin, gout = BnG1(), BnG1()
        gin.hash_and_map_to(msg)
        g1mul(gout, basePoint, random)
        g1add(gout, gin, gout)  # IN + r * G
        return gout.serialize()

    def unblind(self, _in: bytes, random: BnFr):
        gin, gout = BnG1(), BnG1()
        gin.deserialize(_in)
        g1mul(gout, self, random)
        g1sub(gout, gin, gout)  # IN - r * Q
        return gout.serialize()

    @property
    def x(self):
        return self.xy[0]

    @property
    def y(self):
        return self.xy[1]

    @property
    def xy(self):
        from Crypto.Math.Numbers import Integer
        s = self.get_string(16)
        if s == "0":
            return Integer(0), Integer(0)
        else:
            tokens = s.split()
            x = int(tokens[1], 16)
            y = int(tokens[2], 16)
            return Integer(x), Integer(y)

    def size_in_bytes(self):
        """Size of each coordinate, in bytes."""
        return (self.size_in_bits() + 7) // 8

    def size_in_bits(self):
        """Size of each coordinate, in bits."""
        return 254

    def export_key(self, **kwargs):
        from Crypto.PublicKey.ECC import EccKey
        key = EccKey(curve="bn254", point=self)
        return key.export_key(**kwargs)


def generate():
    sk = SecretKey()
    sk.set_by_csprng()
    return sk


def rand():
    random = BnFr()
    random.set_by_csprng()
    return random
