/**********************************************************************
 * Copyright (c) 2020-2026 tecnovert                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSAOTVES_TESTS
#define SECP256K1_MODULE_ECDSAOTVES_TESTS

#include "../../../include/secp256k1_ecdsaotves.h"

void test_ecdsaotves(void) {
    int i;
    unsigned char msg_hash[32];
    unsigned char s[32], e[32], r[32], S[33] ,E[33], cipher_text[ECDSA_OTVES_SIZE], sig[100];
    secp256k1_pubkey pubkey;
    size_t len = 33;
    size_t siglen = 100;

    testutil_random_scalar_order_b32(s);
    testutil_random_scalar_order_b32(e);
    for (i = 0; i < 32; i++) {
        msg_hash[i] = i;
    }
    CHECK(secp256k1_ec_pubkey_create(CTX, &pubkey, e) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, E, &len, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(secp256k1_ec_pubkey_create(CTX, &pubkey, s) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, S, &len, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

    CHECK(ecdsaotves_enc_sign(CTX, cipher_text, s, E, msg_hash) == 1);
    CHECK(ecdsaotves_enc_verify(CTX, S, E, msg_hash, cipher_text) == 1);
    CHECK(ecdsaotves_dec_sig(CTX, sig, &siglen, e, cipher_text) == 1);
    CHECK(ecdsaotves_rec_enc_key(CTX, r, E, cipher_text, sig, siglen) == 1);
    CHECK(secp256k1_memcmp_var(e, r, 32) == 0);
}

void run_ecdsaotves_tests(void) {
    int i;
    for (i = 0; i < COUNT; i++) {
        test_ecdsaotves();
    }
}

/* --- Test registry --- */
static const struct tf_test_entry tests_ecdsaotves[] = {
    CASE1(run_ecdsaotves_tests)
};

#endif
