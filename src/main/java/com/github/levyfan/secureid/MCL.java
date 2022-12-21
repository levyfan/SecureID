package com.github.levyfan.secureid;

import com.sun.jna.Memory;
import com.sun.jna.Native;

import java.util.Arrays;

public class MCL {

    static final int mclBn_CurveFp254BNb = 0;
    static final int MCLBN_FP_UNIT_SIZE;
    static final int MCLBN_FR_UNIT_SIZE;
    static final int MCLBN_COMPILED_TIME_VAR;
    static final int MCL_MAP_TO_MODE_ORIGINAL = 0;
    static final G1 basePoint;

    static native int mclBn_init(int curve, int compiledTimeVar);
    static native int mclBn_setMapToMode(int mode);
    static native int mclBn_getG1ByteSize();
    static native int mclBn_getFrByteSize();
    static native int mclBnFr_setByCSPRNG(Fr x);
    static native long mclBnFr_serialize(byte[] buf, long maxBufSize, Fr x);
    static native long mclBnFr_deserialize(Fr x, byte[] buf, long bufSize);
    static native int mclBnG1_hashAndMapTo(G1 gx, byte[] buf, long bufSize);
    static native void mclBnG1_mul(G1 gz, G1 gx, Fr fy);
    static native void mclBnG1_add(G1 z, G1 x, G1 y);
    static native void mclBnG1_sub(G1 z, G1 x, G1 y);
    static native long mclBnG1_serialize(byte[] buf, long maxBufSize, G1 gx);
    static native long mclBnG1_deserialize(G1 gx, byte[] buf, long bufSize);
    static native int mclBnG1_setStr(G1 x, byte[] buf, long bufSize, int ioMode);
    static native void mclBnFr_setInt32(Fr y, int x);

    static {
        MCLBN_FP_UNIT_SIZE = 4;
        MCLBN_FR_UNIT_SIZE = 4;
        MCLBN_COMPILED_TIME_VAR = ((MCLBN_FR_UNIT_SIZE) * 10 + (MCLBN_FP_UNIT_SIZE));
        Native.register("mclbn256");
        mclBn_init(mclBn_CurveFp254BNb, MCLBN_COMPILED_TIME_VAR);
        mclBn_setMapToMode(MCL_MAP_TO_MODE_ORIGINAL);
        basePoint = new G1();
        basePoint.setString("1 0x2523648240000001BA344D80000000086121000000000013A700000000000012 0x01", 16);
    }

    public static class G1 extends Memory {

        static final int SIZEOF_G1 = MCLBN_FP_UNIT_SIZE * 8 * 3;

        G1() {
            super(SIZEOF_G1);
        }

        void hashAndMapTo(byte[] buf) {
            int err = mclBnG1_hashAndMapTo(this, buf, buf.length);
            if (err != 0) {
                throw new IllegalArgumentException("err mclBnG1_hashAndMapTo " + err);
            }
        }

        void setString(String s, int base) {
            byte[] buf = s.getBytes();
            int err = mclBnG1_setStr(this, buf, buf.length, base);
            if (err != 0) {
                throw new IllegalArgumentException(("err mclBnG1_setStr " + err));
            }
        }

        public byte[] serialize() {
            byte[] buf = new byte[mclBn_getG1ByteSize()];
            long n = mclBnG1_serialize(buf, buf.length, this);
            if (n == 0) {
                throw new IllegalArgumentException("err mclBnG1_serialize");
            }
            return buf;
        }

        public void deserialize(byte[] buf) {
            long n = mclBnG1_deserialize(this, buf, buf.length);
            if (n == 0 || n != buf.length) {
                throw new IllegalArgumentException("err mclBnG1_deserialize " + Arrays.toString(buf));
            }
        }
    }

    public static class Fr extends Memory {

        static final int SIZEOF_FR = MCLBN_FR_UNIT_SIZE * 8;

        Fr() {
            super(SIZEOF_FR);
        }

        public static Fr rand() {
            Fr fr = new Fr();
            fr.setByCSPRNG();
            return fr;
        }

        void setByCSPRNG() {
            int err = mclBnFr_setByCSPRNG(this);
            if (err != 0) {
                throw new IllegalArgumentException("err mclBnFr_setByCSPRNG");
            }
        }

        void setInt(int v) {
            mclBnFr_setInt32(this, v);
        }

        public byte[] serialize() {
            byte[] buf = new byte[mclBn_getFrByteSize()];
            long n = mclBnFr_serialize(buf, buf.length, this);
            if (n == 0) {
                throw new IllegalArgumentException("err mclBnFr_serialize");
            }
            return buf;
        }

        public void deserialize(byte[] buf) {
            long n = mclBnFr_deserialize(this, buf, buf.length);
            if (n == 0 || n != buf.length) {
                throw new IllegalArgumentException("err mclBnFr_deserialize " + Arrays.toString(buf));
            }
        }
    }

    static void g1Mul(G1 out, G1 x, Fr y) {
        mclBnG1_mul(out, x, y);
    }

    static void g1Add(G1 out, G1 x, G1 y) {
        mclBnG1_add(out, x, y);
    }

    static void g1Sub(G1 out, G1 x, G1 y) {
        mclBnG1_sub(out, x, y);
    }
}
