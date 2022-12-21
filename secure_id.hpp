#ifndef SECUREID_SECURE_ID_HPP
#define SECUREID_SECURE_ID_HPP

#include <mcl/bn256.hpp>


namespace SecureID {

    class Init {
    public:
        Init() {
            mcl::bn::initPairing();
            mcl::bn::setMapToMode(MCL_MAP_TO_MODE_ORIGINAL);
            basePoint.setStr("1 0x2523648240000001BA344D80000000086121000000000013A700000000000012 0x01", 16);
        }

        mcl::bn::G1 basePoint;
    };

    inline Init _init;

    class PublicKey : public mcl::bn::G1 {
    public:
        void blind(unsigned char out[32], const char *msg, size_t msg_len, const mcl::bn::Fr* random) {
            mcl::bn::G1 gin, gout;
            mcl::bn::hashAndMapToG1(gin, msg, msg_len);
            mcl::bn::G1::mul(gout, _init.basePoint, *random);
            mcl::bn::G1::add(gout, gin, gout); // IN + r * G
            gout.serialize(out, 32);
        }

        void unblind(unsigned char out[32], unsigned char in[32], const mcl::bn::Fr* random) {
            mcl::bn::G1 gin, gout;
            gin.deserialize(in, 32);
            mcl::bn::G1::mul(gout, *this, *random);
            mcl::bn::G1::sub(gout, gin, gout); // IN - r * Q
            gout.serialize(out, 32);
        }
    };

    class SecretKey : public mcl::bn::Fr {
    public:
        static SecretKey generate() {
            SecretKey sk;
            sk.setByCSPRNG();
            return sk;
        }

        void sign1(unsigned char out[32], const char *msg, size_t msg_len) {
            mcl::bn::G1 gin, gout;
            mcl::bn::hashAndMapToG1(gin, msg, msg_len);
            mcl::bn::G1::mul(gout, gin, *this);
            gout.serialize(out, 32);
        }

        void sign2(unsigned char out[32], unsigned char in[32]) {
            mcl::bn::G1 gin, gout;
            gin.deserialize(in, 32);
            mcl::bn::G1::mul(gout, gin, *this);
            gout.serialize(out, 32);
        }

        PublicKey public_key() {
            PublicKey pk;
            mcl::bn::G1::mul(pk, _init.basePoint, *this);
            return pk;
        }
    };
}

#endif //SECUREID_SECURE_ID_HPP
