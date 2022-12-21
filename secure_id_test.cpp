#include "gtest/gtest.h"
#include "secure_id.hpp"

class SecureIDTest : public ::testing::Test {
protected:
    void SetUp() override {
        secret_key = SecureID::SecretKey::generate();
        public_key = secret_key.public_key();
    }

    void TearDown() override {
    }

    SecureID::SecretKey secret_key;
    SecureID::PublicKey public_key;
};

TEST_F(SecureIDTest, compute) {
    const char msg[9] = "38654201";

    unsigned char signed_id[32];
    secret_key.sign1(signed_id, msg, 8);

    mcl::bn::Fr random;
    random.setByCSPRNG();

    unsigned char blinded[32], signed2[32], unblinded[32];
    public_key.blind(blinded, msg, 8, &random);
    secret_key.sign2(signed2, blinded);
    public_key.unblind(unblinded, signed2, &random);

    for (int i = 0; i < 32; ++i) {
        ASSERT_EQ(signed_id[i], unblinded[i]);
    }
}

TEST_F(SecureIDTest, sign1) {
    SecureID::SecretKey sk;
    *reinterpret_cast<mcl::bn::Fr*>(&sk) = 123456;

    unsigned char signed_id[32];
    sk.sign1(signed_id, "hello world", 11);

    char hex[64];
    char *ptr = hex;
    for (unsigned char i : signed_id) {
        ptr += sprintf(ptr, "%02x", i);
    }

    ASSERT_STREQ("120a19ba42d66e3b07f9b1042ecc241658b98fbd0066ac3a98ec7cd55e487b15", hex);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
