#ifndef SECUREID_SECURE_ID_HPP
#define SECUREID_SECURE_ID_HPP

#include <mcl/bn256.hpp>


namespace SecureID {

#define SID_BYTE_SIZE 32

    class Init {
    public:
        Init() {
            mcl::bn::initPairing();
            if (!mcl::bn::setMapToMode(MCL_MAP_TO_MODE_ORIGINAL)) {
                throw std::invalid_argument("SetMapToMode");
            }
            basePoint.setStr("1 0x2523648240000001BA344D80000000086121000000000013A700000000000012 0x01", 16);
        }

        mcl::bn::G1 basePoint;
    };

    inline Init _init;

    class PublicKey : public mcl::bn::G1 {
    public:
        void blind(unsigned char out[SID_BYTE_SIZE], const char *msg, size_t msg_len, const mcl::bn::Fr* random) {
            mcl::bn::G1 gin, gout;
            mcl::bn::hashAndMapToG1(gin, msg, msg_len);
            mcl::bn::G1::mul(gout, _init.basePoint, *random);
            mcl::bn::G1::add(gout, gin, gout); // IN + r * G
            size_t n = gout.serialize(out, SID_BYTE_SIZE);
            if (n == 0) {
                throw std::invalid_argument("err serialize");
            }
        }

        void unblind(unsigned char out[SID_BYTE_SIZE], unsigned char in[SID_BYTE_SIZE], const mcl::bn::Fr* random) {
            mcl::bn::G1 gin, gout;
            size_t n = gin.deserialize(in, SID_BYTE_SIZE);
            if (n != SID_BYTE_SIZE) {
                throw std::invalid_argument("err deserialize");
            }
            mcl::bn::G1::mul(gout, *this, *random);
            mcl::bn::G1::sub(gout, gin, gout); // IN - r * Q
            n = gout.serialize(out, SID_BYTE_SIZE);
            if (n == 0) {
                throw std::invalid_argument("err serialize");
            }
        }
    };

    class SecretKey : public mcl::bn::Fr {
    public:
        static SecretKey generate() {
            SecretKey sk;
            sk.setByCSPRNG();
            return sk;
        }

        void sign1(unsigned char out[SID_BYTE_SIZE], const char *msg, size_t msg_len) {
            mcl::bn::G1 gin, gout;
            mcl::bn::hashAndMapToG1(gin, msg, msg_len);
            mcl::bn::G1::mul(gout, gin, *this);
            size_t n = gout.serialize(out, SID_BYTE_SIZE);
            if (n == 0) {
                throw std::invalid_argument("err serialize");
            }
        }

        void sign2(unsigned char out[SID_BYTE_SIZE], unsigned char in[SID_BYTE_SIZE]) {
            mcl::bn::G1 gin, gout;
            size_t n = gin.deserialize(in, SID_BYTE_SIZE);
            if (n != SID_BYTE_SIZE) {
                throw std::invalid_argument("err deserialize");
            }
            mcl::bn::G1::mul(gout, gin, *this);
            n = gout.serialize(out, SID_BYTE_SIZE);
            if (n == 0) {
                throw std::invalid_argument("err serialize");
            }
        }

        PublicKey public_key() {
            PublicKey pk;
            mcl::bn::G1::mul(pk, _init.basePoint, *this);
            return pk;
        }
    };
}

#endif //SECUREID_SECURE_ID_HPP
