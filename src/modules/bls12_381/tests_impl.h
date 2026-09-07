/**********************************************************************
 * Copyright (c) 2024                                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BLS12_381_TESTS
#define SECP256K1_MODULE_BLS12_381_TESTS

#include "../../../include/secp256k1_bls12_381.h"
#include "../../unit_test.h"

/* Fr group order r, big-endian. */
static const unsigned char bls_fr_order_be[32] = {
    0x73,0xed,0xa7,0x53,0x29,0x9d,0x7d,0x48,0x33,0x39,0xd8,0x08,0x09,0xa1,0xd8,0x05,
    0x53,0xbd,0xa4,0x02,0xff,0xfe,0x5b,0xfe,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01
};

static int bls_pt_eq(const secp256k1_bls_point *a, const secp256k1_bls_point *b) {
    unsigned char ba[48], bb[48];
    secp256k1_bls_point_serialize(ba, a);
    secp256k1_bls_point_serialize(bb, b);
    return secp256k1_memcmp_var(ba, bb, 48) == 0;
}

static int bls_sc_eq(const secp256k1_bls_scalar *a, const secp256k1_bls_scalar *b) {
    unsigned char ba[32], bb[32];
    secp256k1_bls_scalar_get_b32(ba, a);
    secp256k1_bls_scalar_get_b32(bb, b);
    return secp256k1_memcmp_var(ba, bb, 32) == 0;
}

static void test_bls_scalars(void) {
    unsigned char b_one[32], b_val[32], out[32], b_max[32];
    secp256k1_bls_scalar one, val, r, t;
    size_t i;

    memset(b_one, 0, 32); b_one[31] = 1;
    memset(b_val, 0, 32); b_val[31] = 5;
    memset(b_max, 0xff, 32);

    /* set/get round-trip */
    CHECK(secp256k1_bls_scalar_set_b32(&one, b_one) == 1);
    secp256k1_bls_scalar_get_b32(out, &one);
    CHECK(secp256k1_memcmp_var(out, b_one, 32) == 0);

    /* canonical check: order itself and 0xff..ff are rejected */
    CHECK(secp256k1_bls_scalar_set_b32(&r, bls_fr_order_be) == 0);
    CHECK(secp256k1_bls_scalar_set_b32(&r, b_max) == 0);

    /* zero test */
    CHECK(secp256k1_bls_scalar_is_zero(&one) == 0);
    secp256k1_bls_scalar_negate(&t, &one);
    secp256k1_bls_scalar_add(&t, &t, &one);      /* (-1) + 1 == 0 */
    CHECK(secp256k1_bls_scalar_is_zero(&t) == 1);

    /* inverse: val * val^-1 == 1 */
    CHECK(secp256k1_bls_scalar_set_b32(&val, b_val) == 1);
    secp256k1_bls_scalar_inverse(&t, &val);
    secp256k1_bls_scalar_mul(&t, &t, &val);
    CHECK(bls_sc_eq(&t, &one));

    /* (r-1) is accepted, (r-1)+1 == 0 */
    memcpy(out, bls_fr_order_be, 32);
    for (i = 32; i > 0; i--) { if (out[i-1]-- != 0) break; }   /* out = r-1 */
    CHECK(secp256k1_bls_scalar_set_b32(&t, out) == 1);
    secp256k1_bls_scalar_add(&t, &t, &one);
    CHECK(secp256k1_bls_scalar_is_zero(&t) == 1);
}

static void test_bls_points(void) {
    secp256k1_bls_point A, B, A2, APP, D, inf, S;
    secp256k1_bls_scalar two;
    unsigned char b_two[32], ser[48], bad[48];
    size_t i;

    memset(b_two, 0, 32); b_two[31] = 2;
    CHECK(secp256k1_bls_scalar_set_b32(&two, b_two) == 1);

    /* generators parse and round-trip */
    CHECK(secp256k1_bls_point_parse(&A, secp256k1_bls_gen_a) == 1);
    CHECK(secp256k1_bls_point_parse(&B, secp256k1_bls_gen_b) == 1);
    secp256k1_bls_point_serialize(ser, &A);
    CHECK(secp256k1_memcmp_var(ser, secp256k1_bls_gen_a, 48) == 0);
    CHECK(!bls_pt_eq(&A, &B));   /* independent generators */

    /* 2*A == A + A */
    secp256k1_bls_point_mul(&A2, &A, &two);
    secp256k1_bls_point_add(&APP, &A, &A);
    CHECK(bls_pt_eq(&A2, &APP));

    /* 2A - A == A */
    secp256k1_bls_point_sub(&D, &A2, &A);
    CHECK(bls_pt_eq(&D, &A));

    /* A + inf == A */
    secp256k1_bls_point_set_infinity(&inf);
    secp256k1_bls_point_add(&S, &A, &inf);
    CHECK(bls_pt_eq(&S, &A));

    /* parse must reject: the infinity encoding, and garbage */
    secp256k1_bls_point_serialize(ser, &inf);
    CHECK(secp256k1_bls_point_parse(&S, ser) == 0);
    for (i = 0; i < 48; i++) { bad[i] = 0xff; }
    CHECK(secp256k1_bls_point_parse(&S, bad) == 0);
}

void run_bls12_381_tests(void) {
    int i;
    printf("Running BLS12-381 tests.\n");
    for (i = 0; i < COUNT; i++) {
        test_bls_scalars();
        test_bls_points();
    }
}

/* --- Test registry --- */
static const struct tf_test_entry tests_bls12_381[] = {
    CASE1(run_bls12_381_tests)
};

#endif
