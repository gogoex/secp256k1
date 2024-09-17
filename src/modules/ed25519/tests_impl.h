/**********************************************************************
 * Copyright (c) 2020 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ED25519_TESTS
#define SECP256K1_MODULE_ED25519_TESTS

#include "../../../include/secp256k1_ed25519.h"

void test_ed25519_infinity(void) {
    ge25519_p3 Q, R, P;
    ge25519_p1p1 r_p1p1;
    ge25519_cached q_cached;
    unsigned char tmp[32];

    /* Set infinity / identity */
    ge25519_scalarmult_base(&Q, ed25519_sc_zero);

    /* A + inf == A */
    ge25519_frombytes(&P, ed25519_gen2);
    ge25519_p3_to_cached(&q_cached, &P);
    ge25519_add(&r_p1p1, &Q, &q_cached);
    ge25519_p1p1_to_p3(&R, &r_p1p1);
    ge25519_p3_tobytes(tmp, &R);
    CHECK(secp256k1_memcmp_var(tmp, ed25519_gen2, 32) == 0);

    ge25519_p3_tobytes(tmp, &Q);
    CHECK(_crypto_scalarmult_ed25519_is_inf(tmp) == 1);
    CHECK(ge25519_frombytes(&Q, tmp) == 0);
    CHECK(crypto_core_ed25519_is_valid_point(tmp) == 0);
}

void run_ed25519_tests(void) {
    int rv;
    unsigned char k1[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
    };
    unsigned char k2[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00,
    };
    unsigned char T1[32] = {
        0x97, 0xab, 0x99, 0x32, 0x63, 0x4c, 0x2a, 0x71,
        0xde, 0xd4, 0x09, 0xc7, 0x3e, 0x84, 0xd6, 0x44,
        0x87, 0xdc, 0xc2, 0x24, 0xf9, 0x72, 0x8f, 0xde,
        0x24, 0xef, 0x33, 0x27, 0x78, 0x2e, 0x68, 0xc3,
    };
    unsigned char T2[32] = {
        0xad, 0xe1, 0x23, 0x2c, 0x10, 0x1e, 0x6e, 0x42,
        0x56, 0x4b, 0x97, 0xac, 0x2b, 0x38, 0x38, 0x7a,
        0x50, 0x9d, 0xf0, 0xa3, 0x1d, 0x38, 0xe3, 0x6b,
        0xf4, 0xbd, 0xf4, 0xad, 0x2f, 0x4f, 0x55, 0x73
    };
    unsigned char r[32], K1[32], K2[32], K3[32];

    CHECK(crypto_core_ed25519_bytes() == 32);


    memset(r, 0, 32);

    crypto_core_ed25519_scalar_add(r, k1, k2);
    CHECK(secp256k1_memcmp_var(r, k2, 32) > 0);

    crypto_core_ed25519_scalar_sub(r, r, k2);
    CHECK(secp256k1_memcmp_var(r, k1, 32) == 0);

    rv = crypto_scalarmult_ed25519_base_noclamp(K1, k1);
    CHECK(rv == 0);

    rv = crypto_scalarmult_ed25519_base(K2, k2);
    CHECK(rv == 0);

    rv = crypto_core_ed25519_add(r, K1, K2);
    CHECK(rv == 0);

    rv = crypto_core_ed25519_sub(r, r, K2);
    CHECK(rv == 0);
    CHECK(secp256k1_memcmp_var(r, K1, 32) == 0);

    CHECK(crypto_scalarmult_ed25519_noclamp(K3, k1, ed25519_gen) == 0);
    CHECK(secp256k1_memcmp_var(K3, K1, 32) == 0);

    CHECK(ed25519_hash_to_curve_repeat(r, T1) == 1);
    CHECK(secp256k1_memcmp_var(r, T2, 32) == 0);


    CHECK(ed25519_hash_to_curve_repeat(r, ed25519_gen) == 1);
    CHECK(secp256k1_memcmp_var(r, ed25519_gen2, 32) == 0);

    CHECK(ed25519_hash_to_curve_elligator(r, ed25519_gen) == 1);

    CHECK(0 == ed25519_less_than_l_be(ed25519_sc_group_order_be));

    test_ed25519_infinity();
}

/* --- Test registry --- */
static const struct tf_test_entry tests_ed25519[] = {
    CASE1(run_ed25519_tests)
};

#endif
