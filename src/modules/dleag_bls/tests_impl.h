/**********************************************************************
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_DLEAG_BLS_TESTS
#define SECP256K1_MODULE_DLEAG_BLS_TESTS

#include "../../../include/secp256k1_dleag_bls.h"
#include "../../unit_test.h"

static void test_dbls_proof_size(void) {
    /* header: secp pk + G1 pk + ECDSA + Schnorr-G1 */
    const size_t hdr = 33 + 48 + 64 + 80;
    /* per bit: C_G + C_B + a0 + a1 + b0 + b1 */
    const size_t per_bit = 33 + 48 + 4 * 32;

    CHECK(hdr == 225);
    CHECK(per_bit == 209);
    CHECK(dbls_proof_size(1) == hdr + 64 + per_bit);
    CHECK(dbls_proof_size(252) == hdr + 64 + 252 * per_bit);
    CHECK(dbls_proof_size(252) == 52957);
    CHECK(secp256k1_bls_dleag_size(1) == dbls_proof_size(1));
    CHECK(secp256k1_bls_dleag_size(252) == 52957);

    /* prove accepts a buffer of exactly dbls_proof_size bytes and rejects one byte less. */
    {
        unsigned char key[32], nonce[32];
        unsigned char proof[52957];
        size_t len;

        testrand256(key);
        key[0] = (key[0] & 0x0f) | 0x08;   /* 2^251 <= key < 2^252: fits 252 bits, passes x >= 2^16 */
        testrand256(nonce);

        len = dbls_proof_size(252) - 1;
        CHECK(secp256k1_bls_dleag_prove(CTX, proof, &len, key, 252, nonce) == 0);
        CHECK(len == dbls_proof_size(252) - 1);   /* untouched on failure */

        len = dbls_proof_size(252);
        CHECK(secp256k1_bls_dleag_prove(CTX, proof, &len, key, 252, nonce) == 1);
        CHECK(len == dbls_proof_size(252));
    }
}

static void test_dbls_dleag_hash(void) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    unsigned char pre[32], bJ[33], bK[48];
    unsigned char buf[32 + 33 + 48 + 4 + 4];
    unsigned char out[32], exp[32], tmp[32];
    secp256k1_sha256 h;

    testrand256(pre);
    testrand_bytes_test(bJ, sizeof(bJ));
    testrand_bytes_test(bK, sizeof(bK));

    /* 1. Equals SHA256 over the flat concatenation; i, j big-endian. */
    memcpy(buf, pre, 32);
    memcpy(buf + 32, bJ, 33);
    memcpy(buf + 65, bK, 48);
    buf[113] = 0x01; buf[114] = 0x02; buf[115] = 0x03; buf[116] = 0x04;
    buf[117] = 0x0a; buf[118] = 0x0b; buf[119] = 0x0c; buf[120] = 0x0d;
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(hash_ctx, &h, buf, sizeof(buf));
    secp256k1_sha256_finalize(hash_ctx, &h, exp);
    dbls_dleag_hash(out, hash_ctx, pre, bJ, 33, bK, 48, 0x01020304, 0x0a0b0c0d);
    CHECK(secp256k1_memcmp_var(out, exp, 32) == 0);

    /* 2. len_k is honoured: hashing 32 of the 48 bytes gives a different result. */
    dbls_dleag_hash(tmp, hash_ctx, pre, bJ, 33, bK, 32, 0x01020304, 0x0a0b0c0d);
    CHECK(secp256k1_memcmp_var(out, tmp, 32) != 0);

    /* 3. Ring index i and slot j each change the output. */
    dbls_dleag_hash(tmp, hash_ctx, pre, bJ, 33, bK, 48, 0x01020305, 0x0a0b0c0d);
    CHECK(secp256k1_memcmp_var(out, tmp, 32) != 0);
    dbls_dleag_hash(tmp, hash_ctx, pre, bJ, 33, bK, 48, 0x01020304, 0x0a0b0c0e);
    CHECK(secp256k1_memcmp_var(out, tmp, 32) != 0);

    /* 4. Tampering: flipping one random bit in any input changes the output. */
    {
        unsigned char pre2[32], bJ2[33], bK2[48];
        memcpy(pre2, pre, 32); testrand_flip(pre2, 32);
        dbls_dleag_hash(tmp, hash_ctx, pre2, bJ, 33, bK, 48, 0x01020304, 0x0a0b0c0d);
        CHECK(secp256k1_memcmp_var(out, tmp, 32) != 0);
        memcpy(bJ2, bJ, 33); testrand_flip(bJ2, 33);
        dbls_dleag_hash(tmp, hash_ctx, pre, bJ2, 33, bK, 48, 0x01020304, 0x0a0b0c0d);
        CHECK(secp256k1_memcmp_var(out, tmp, 32) != 0);
        memcpy(bK2, bK, 48); testrand_flip(bK2, 48);
        dbls_dleag_hash(tmp, hash_ctx, pre, bJ, 33, bK2, 48, 0x01020304, 0x0a0b0c0d);
        CHECK(secp256k1_memcmp_var(out, tmp, 32) != 0);
    }
}

static const unsigned char dbls_secp_order_be[32] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
};

static void dbls_test_sha256(unsigned char *out32, const unsigned char *in32) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(hash_ctx, &sha, in32, 32);
    secp256k1_sha256_finalize(hash_ctx, &sha, out32);
}

/* Note: the `return 0` after 1000 rehashes in dbls_hash_sc_secp256k1 is not
 * reachable in practice (~2^-128000) and is not tested. */
static void test_dbls_hash_to_scalar(void) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    static const unsigned char zero[32] = {0};
    unsigned char in[32], in2[32], h[32];
    secp256k1_scalar ss, ss2, ss_exp;
    secp256k1_bls_scalar bs, bs2, bs_exp;
    int overflow;
    uint32_t k;

    /* secp 1. Valid input (< n, non-zero) maps through unchanged. */
    testrand256(in); in[0] &= 0x7f;
    CHECK(dbls_hash_sc_secp256k1(&ss, hash_ctx, in) == 1);
    secp256k1_scalar_set_b32(&ss_exp, in, &overflow);
    CHECK(!overflow && secp256k1_scalar_eq(&ss, &ss_exp));

    /* secp 2. Invalid inputs (== n, == 0) are rehashed once: result = SHA256(in). */
    dbls_test_sha256(h, dbls_secp_order_be);
    CHECK(dbls_hash_sc_secp256k1(&ss, hash_ctx, dbls_secp_order_be) == 1);
    secp256k1_scalar_set_b32(&ss_exp, h, &overflow);
    CHECK(!overflow && secp256k1_scalar_eq(&ss, &ss_exp));
    dbls_test_sha256(h, zero);
    CHECK(dbls_hash_sc_secp256k1(&ss, hash_ctx, zero) == 1);
    secp256k1_scalar_set_b32(&ss_exp, h, &overflow);
    CHECK(!overflow && secp256k1_scalar_eq(&ss, &ss_exp));

    /* bls 1. Valid input (< 2^254 < r, non-zero) maps through unchanged. */
    testrand256(in); in[0] &= 0x3f;
    dbls_bls_hash_to_scalar(hash_ctx, &bs, in);
    CHECK(secp256k1_bls_scalar_set_b32(&bs_exp, in) == 1);
    CHECK(bls_sc_eq(&bs, &bs_exp));

    /* bls 2. Top bit set: it is cleared, then the value is accepted without rehash. */
    memcpy(in2, in, 32); in2[0] |= 0x80;
    dbls_bls_hash_to_scalar(hash_ctx, &bs2, in2);
    CHECK(bls_sc_eq(&bs2, &bs_exp));

    /* bls 3. Invalid inputs (== r, == 0) are rehashed once: result = SHA256(in) with top bit cleared. */
    dbls_test_sha256(h, bls_fr_order_be); h[0] &= 0x7f;
    dbls_bls_hash_to_scalar(hash_ctx, &bs, bls_fr_order_be);
    CHECK(secp256k1_bls_scalar_set_b32(&bs_exp, h) == 1);
    CHECK(bls_sc_eq(&bs, &bs_exp));
    dbls_test_sha256(h, zero); h[0] &= 0x7f;
    dbls_bls_hash_to_scalar(hash_ctx, &bs, zero);
    CHECK(secp256k1_bls_scalar_set_b32(&bs_exp, h) == 1);
    CHECK(bls_sc_eq(&bs, &bs_exp));

    /* 4. Deterministic, and flipping any one of bits 0..254 changes both scalars. */
    testrand256(in);
    CHECK(dbls_hash_sc_secp256k1(&ss, hash_ctx, in) == 1);
    CHECK(dbls_hash_sc_secp256k1(&ss2, hash_ctx, in) == 1);
    CHECK(secp256k1_scalar_eq(&ss, &ss2));
    dbls_bls_hash_to_scalar(hash_ctx, &bs, in);
    dbls_bls_hash_to_scalar(hash_ctx, &bs2, in);
    CHECK(bls_sc_eq(&bs, &bs2));

    k = testrand_int(255);
    memcpy(in2, in, 32);
    in2[31 - k / 8] ^= (unsigned char)(1 << (k % 8));
    CHECK(dbls_hash_sc_secp256k1(&ss2, hash_ctx, in2) == 1);
    CHECK(!secp256k1_scalar_eq(&ss, &ss2));
    dbls_bls_hash_to_scalar(hash_ctx, &bs2, in2);
    CHECK(!bls_sc_eq(&bs, &bs2));

    /* 5. bls only: bit 255 is masked away, so flipping it does NOT change the BLS scalar. */
    memcpy(in2, in, 32);
    in2[0] ^= 0x80;
    dbls_bls_hash_to_scalar(hash_ctx, &bs2, in2);
    CHECK(bls_sc_eq(&bs, &bs2));
}

/* Note: for dbls_get_sc_secp256k1 the rejection path (draw >= n or == 0) is
 * not reachable in practice (~2^-128) and is not tested. */
static void test_dbls_get_sc(void) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    secp256k1_rfc6979_hmac_sha256 rng1, rng2;
    unsigned char seed[32], seed2[32], raw[32];
    secp256k1_scalar s1, s2, s_prev;
    secp256k1_bls_scalar b1, b2, b_prev, b_raw, b_exp;
    int i, found = 0;

    /* 1. Same seed -> same sequence; values non-zero; consecutive draws differ. */
    testrand256(seed);
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng1, seed, 32);
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng2, seed, 32);
    for (i = 0; i < 16; ++i) {
        dbls_get_sc_secp256k1(&s1, hash_ctx, &rng1);
        dbls_get_sc_secp256k1(&s2, hash_ctx, &rng2);
        CHECK(secp256k1_scalar_eq(&s1, &s2));
        CHECK(!secp256k1_scalar_is_zero(&s1));
        dbls_bls_get_sc(&b1, hash_ctx, &rng1);
        dbls_bls_get_sc(&b2, hash_ctx, &rng2);
        CHECK(bls_sc_eq(&b1, &b2));
        CHECK(!secp256k1_bls_scalar_is_zero(&b1));
        if (i > 0) {
            CHECK(!secp256k1_scalar_eq(&s1, &s_prev));
            CHECK(!bls_sc_eq(&b1, &b_prev));
        }
        s_prev = s1;
        b_prev = b1;
    }
    secp256k1_rfc6979_hmac_sha256_finalize(&rng1);
    secp256k1_rfc6979_hmac_sha256_finalize(&rng2);

    /* 2. Different seed -> different first draw. */
    memcpy(seed2, seed, 32);
    seed2[31] ^= 1;
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng1, seed, 32);
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng2, seed2, 32);
    dbls_get_sc_secp256k1(&s1, hash_ctx, &rng1);
    dbls_get_sc_secp256k1(&s2, hash_ctx, &rng2);
    CHECK(!secp256k1_scalar_eq(&s1, &s2));
    dbls_bls_get_sc(&b1, hash_ctx, &rng1);
    dbls_bls_get_sc(&b2, hash_ctx, &rng2);
    CHECK(!bls_sc_eq(&b1, &b2));
    secp256k1_rfc6979_hmac_sha256_finalize(&rng1);
    secp256k1_rfc6979_hmac_sha256_finalize(&rng2);

    /* 3. bls rejection path: deterministically find a seed whose first masked
     *    DRBG output is >= r. The sampler must skip it (not reduce it mod r)
     *    and return the next valid output. */
    memset(seed, 0, 32);
    for (i = 0; i < 256 && !found; ++i) {
        seed[0] = (unsigned char)i;
        secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng1, seed, 32);
        secp256k1_rfc6979_hmac_sha256_generate(hash_ctx, &rng1, raw, 32);
        raw[0] &= 0x7f;
        found = !secp256k1_bls_scalar_set_b32(&b_raw, raw);
        if (found) {
            secp256k1_rfc6979_hmac_sha256_generate(hash_ctx, &rng1, raw, 32);
            raw[0] &= 0x7f;
            CHECK(secp256k1_bls_scalar_set_b32(&b_exp, raw) == 1);   /* second output is valid */
        }
        secp256k1_rfc6979_hmac_sha256_finalize(&rng1);
    }
    CHECK(found);
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng1, seed, 32);
    dbls_bls_get_sc(&b1, hash_ctx, &rng1);
    secp256k1_rfc6979_hmac_sha256_finalize(&rng1);
    CHECK(bls_sc_eq(&b1, &b_exp));
}

/* Note: ss = 0 yields the point at infinity, on which secp256k1_gej_serialize
 * aborts (VERIFY_CHECK / illegal callback) instead of returning 0, so that
 * path is not testable here. prove never passes a zero scalar. */
static void test_dbls_raise_point_encode(void) {
    secp256k1_scalar ss, minus_one;
    secp256k1_gej gj_g, gj_h, rj;
    secp256k1_ge ge_h, r;
    secp256k1_pubkey pk;
    unsigned char sk[32], out[33], exp[33], h33[33];
    size_t len = 33;

    secp256k1_gej_set_ge(&gj_g, &secp256k1_ge_const_g);
    secp256k1_generator_load(&ge_h, &secp256k1_generator_const_h);
    secp256k1_gej_set_ge(&gj_h, &ge_h);

    /* 1. P = G: matches the standard pubkey path. */
    testutil_random_scalar_order(&ss);
    secp256k1_scalar_get_b32(sk, &ss);
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, sk) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, exp, &len, &pk, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(dbls_raise_point_encode(CTX, out, &gj_g, &ss) == 1);
    CHECK(secp256k1_memcmp_var(out, exp, 33) == 0);

    /* 2. P = H: matches constant-time ecmult (independent algorithm). */
    secp256k1_ecmult_const(&rj, &ge_h, &ss);
    secp256k1_ge_set_gej(&r, &rj);
    secp256k1_pubkey_save(&pk, &r);
    len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(CTX, exp, &len, &pk, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(dbls_raise_point_encode(CTX, out, &gj_h, &ss) == 1);
    CHECK(secp256k1_memcmp_var(out, exp, 33) == 0);

    /* 3. ss = 1: 1*H is H itself (SEC1 encoding; secp256k1_generator_serialize
     *    uses a different prefix byte, 0x0a/0x0b, so it is not used here). */
    secp256k1_pubkey_save(&pk, &ge_h);
    len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(CTX, h33, &len, &pk, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(dbls_raise_point_encode(CTX, out, &gj_h, &secp256k1_scalar_one) == 1);
    CHECK(secp256k1_memcmp_var(out, h33, 33) == 0);

    /* 4. ss = -1: same x as H, opposite y parity (prefix 0x02 <-> 0x03). */
    secp256k1_scalar_negate(&minus_one, &secp256k1_scalar_one);
    CHECK(dbls_raise_point_encode(CTX, out, &gj_h, &minus_one) == 1);
    CHECK(out[0] == (h33[0] ^ 0x01));
    CHECK(secp256k1_memcmp_var(out + 1, h33 + 1, 32) == 0);
}

/* Textbook ECDSA verification over an arbitrary generator, written
 * independently of the code under test: R = (m/s)*gen + (r/s)*P, accept iff
 * R.x mod n == r. */
static int dbls_test_ecdsa_verify_gen(const unsigned char *sig64, const unsigned char *msg32,
                                      const secp256k1_ge *P, const secp256k1_ge *gen) {
    secp256k1_scalar r, s, m, sinv, u1, u2, rx;
    secp256k1_gej gj, pj, rj, t;
    secp256k1_ge R;
    unsigned char xb[32];
    int overflow;

    secp256k1_scalar_set_b32(&r, sig64, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&r)) return 0;
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&s)) return 0;
    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_scalar_inverse_var(&sinv, &s);
    secp256k1_scalar_mul(&u1, &m, &sinv);
    secp256k1_scalar_mul(&u2, &r, &sinv);
    secp256k1_gej_set_ge(&gj, gen);
    secp256k1_gej_set_ge(&pj, P);
    secp256k1_ecmult(&rj, &gj, &u1, &secp256k1_scalar_zero);
    secp256k1_ecmult(&t, &pj, &u2, &secp256k1_scalar_zero);
    secp256k1_gej_add_var(&rj, &rj, &t, NULL);
    if (secp256k1_gej_is_infinity(&rj)) return 0;
    secp256k1_ge_set_gej_var(&R, &rj);
    secp256k1_fe_normalize(&R.x);
    secp256k1_fe_get_b32(xb, &R.x);
    secp256k1_scalar_set_b32(&rx, xb, NULL);
    return secp256k1_scalar_eq(&rx, &r);
}

/* Recover the signing nonce from a signature with known key: k = (m + r*x) / s.
 * Low-s normalisation may have negated s, so k is only known up to sign. */
static void dbls_test_ecdsa_nonce(secp256k1_scalar *k, const unsigned char *sig64,
                                  const unsigned char *msg32, const secp256k1_scalar *x) {
    secp256k1_scalar r, s, m, t;
    secp256k1_scalar_set_b32(&r, sig64, NULL);
    secp256k1_scalar_set_b32(&s, sig64 + 32, NULL);
    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_scalar_mul(&t, &r, x);
    secp256k1_scalar_add(&t, &t, &m);
    secp256k1_scalar_inverse_var(k, &s);
    secp256k1_scalar_mul(k, k, &t);
}

static int dbls_test_scalar_eq_up_to_sign(const secp256k1_scalar *a, const secp256k1_scalar *b) {
    secp256k1_scalar nb;
    secp256k1_scalar_negate(&nb, b);
    return secp256k1_scalar_eq(a, b) || secp256k1_scalar_eq(a, &nb);
}

static void test_dbls_ecdsa_sign_gen(void) {
    unsigned char key[32], msg[32], msg2[32], bad[32];
    unsigned char sig_g[64], sig_h[64], sig2[64], sig_plain[64], zero64[64];
    secp256k1_scalar x, s, k_g, k_h, k_plain;
    secp256k1_gej pj;
    secp256k1_ge ge_g, ge_h, P_g, P_h;
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    int i;

    memset(zero64, 0, 64);
    ge_g = secp256k1_ge_const_g;
    secp256k1_generator_load(&ge_h, &secp256k1_generator_const_h);
    testutil_random_scalar_order(&x);
    secp256k1_scalar_get_b32(key, &x);
    testrand256(msg);
    secp256k1_ecmult_const(&pj, &ge_g, &x); secp256k1_ge_set_gej(&P_g, &pj);
    secp256k1_ecmult_const(&pj, &ge_h, &x); secp256k1_ge_set_gej(&P_h, &pj);

    /* 1. gen = G: a standard ECDSA signature, accepted by secp256k1_ecdsa_verify. */
    CHECK(dbls_ecdsa_sign_gen(CTX, sig_g, msg, key, &secp256k1_generator_const_g) == 1);
    CHECK(secp256k1_ecdsa_signature_parse_compact(CTX, &sig, sig_g) == 1);
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, key) == 1);
    CHECK(secp256k1_ecdsa_verify(CTX, &sig, msg, &pk) == 1);
    CHECK(dbls_test_ecdsa_verify_gen(sig_g, msg, &P_g, &ge_g));

    /* 2. gen = H: accepted by the textbook verifier with P = x*H. */
    CHECK(dbls_ecdsa_sign_gen(CTX, sig_h, msg, key, &secp256k1_generator_const_h) == 1);
    CHECK(dbls_test_ecdsa_verify_gen(sig_h, msg, &P_h, &ge_h));

    /* 3. Low-s for both. */
    secp256k1_scalar_set_b32(&s, sig_g + 32, NULL);
    CHECK(!secp256k1_scalar_is_high(&s));
    secp256k1_scalar_set_b32(&s, sig_h + 32, NULL);
    CHECK(!secp256k1_scalar_is_high(&s));

    /* 4. Deterministic. */
    CHECK(dbls_ecdsa_sign_gen(CTX, sig2, msg, key, &secp256k1_generator_const_h) == 1);
    CHECK(secp256k1_memcmp_var(sig2, sig_h, 64) == 0);

    /* 5. Nonce is domain-separated from plain RFC6979 ECDSA (same key, msg, gen = G). */
    CHECK(secp256k1_ecdsa_sign(CTX, &sig, msg, key, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, sig_plain, &sig) == 1);
    dbls_test_ecdsa_nonce(&k_g, sig_g, msg, &x);
    dbls_test_ecdsa_nonce(&k_plain, sig_plain, msg, &x);
    CHECK(!dbls_test_scalar_eq_up_to_sign(&k_g, &k_plain));

    /* 5b. The tag also matters when plain ECDSA signs the derived nonce message
     *     SHA256(msg || gen33) itself: without the tag both would share k. */
    {
        const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
        unsigned char g33[33], nonce_msg[32];
        secp256k1_sha256 h;
        CHECK(secp256k1_generator_serialize(CTX, g33, &secp256k1_generator_const_g) == 1);
        secp256k1_sha256_initialize(&h);
        secp256k1_sha256_write(hash_ctx, &h, msg, 32);
        secp256k1_sha256_write(hash_ctx, &h, g33, 33);
        secp256k1_sha256_finalize(hash_ctx, &h, nonce_msg);
        CHECK(secp256k1_ecdsa_sign(CTX, &sig, nonce_msg, key, NULL, NULL) == 1);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, sig_plain, &sig) == 1);
        dbls_test_ecdsa_nonce(&k_plain, sig_plain, nonce_msg, &x);
        CHECK(!dbls_test_scalar_eq_up_to_sign(&k_g, &k_plain));
    }

    /* 6. Nonce binds the generator: same (key, msg) under G and H uses different k. */
    dbls_test_ecdsa_nonce(&k_h, sig_h, msg, &x);
    CHECK(!dbls_test_scalar_eq_up_to_sign(&k_g, &k_h));

    /* 7. Invalid keys (0, n, 2^256-1): returns 0 and zeroes the output. */
    for (i = 0; i < 3; ++i) {
        if (i == 0) memset(bad, 0, 32);
        if (i == 1) memcpy(bad, dbls_secp_order_be, 32);
        if (i == 2) memset(bad, 0xff, 32);
        memset(sig2, 0xaa, 64);
        CHECK(dbls_ecdsa_sign_gen(CTX, sig2, msg, bad, &secp256k1_generator_const_h) == 0);
        CHECK(secp256k1_memcmp_var(sig2, zero64, 64) == 0);
    }

    /* 8. Wrong message is rejected. */
    memcpy(msg2, msg, 32); testrand_flip(msg2, 32);
    CHECK(!dbls_test_ecdsa_verify_gen(sig_h, msg2, &P_h, &ge_h));

    /* 9. Wrong generator is rejected: an H-signature does not verify as a G-signature. */
    CHECK(!dbls_test_ecdsa_verify_gen(sig_h, msg, &P_g, &ge_g));

    /* 10. Tampered signature (one bit in r or s) is rejected. */
    memcpy(sig2, sig_h, 64); testrand_flip(sig2, 64);
    CHECK(!dbls_test_ecdsa_verify_gen(sig2, msg, &P_h, &ge_h));
}

/* Schnorr challenge as specified for dbls_bls_sign_gen:
 * e = hash_to_scalar(SHA256(R48 || P48 || msg)). */
static void dbls_test_bls_challenge(secp256k1_bls_scalar *e, const unsigned char *R48,
                                    const unsigned char *P48, const unsigned char *msg, size_t mlen) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    secp256k1_sha256 hs;
    unsigned char buf[32];
    secp256k1_sha256_initialize(&hs);
    secp256k1_sha256_write(hash_ctx, &hs, R48, 48);
    secp256k1_sha256_write(hash_ctx, &hs, P48, 48);
    secp256k1_sha256_write(hash_ctx, &hs, msg, mlen);
    secp256k1_sha256_finalize(hash_ctx, &hs, buf);
    dbls_bls_hash_to_scalar(hash_ctx, e, buf);
}

/* Textbook Schnorr verification on G1, written independently of the code
 * under test: accept iff s*gen == R + e*P. */
static int dbls_test_bls_verify(const unsigned char *sig80, const unsigned char *msg, size_t mlen,
                                const secp256k1_bls_point *P, const unsigned char *gen48) {
    secp256k1_bls_point genp, R, lhs, rhs, eP;
    secp256k1_bls_scalar s, e;
    unsigned char P48[48];

    if (!secp256k1_bls_point_parse(&genp, gen48)) return 0;
    if (!secp256k1_bls_point_parse(&R, sig80)) return 0;
    if (!secp256k1_bls_scalar_set_b32(&s, sig80 + 48)) return 0;
    secp256k1_bls_point_serialize(P48, P);
    dbls_test_bls_challenge(&e, sig80, P48, msg, mlen);
    secp256k1_bls_point_mul(&lhs, &genp, &s);
    secp256k1_bls_point_mul(&eP, P, &e);
    secp256k1_bls_point_add(&rhs, &R, &eP);
    return bls_pt_eq(&lhs, &rhs);
}

/* Recover the nonce from a signature with known key: k = s - e*x. */
static void dbls_test_bls_nonce(secp256k1_bls_scalar *k, const unsigned char *sig80,
                                const secp256k1_bls_point *P, const secp256k1_bls_scalar *x,
                                const unsigned char *msg, size_t mlen) {
    secp256k1_bls_scalar s, e, ex;
    unsigned char P48[48];
    secp256k1_bls_point_serialize(P48, P);
    dbls_test_bls_challenge(&e, sig80, P48, msg, mlen);
    CHECK(secp256k1_bls_scalar_set_b32(&s, sig80 + 48) == 1);
    secp256k1_bls_scalar_mul(&ex, &e, x);
    secp256k1_bls_scalar_negate(&ex, &ex);
    secp256k1_bls_scalar_add(k, &s, &ex);
}

/* Note: removing the nonce tag "DLEAG/BLS/nonce" is not detectable here.
 * Signatures stay valid and the nonce stays bound to (x, gen, msg); testing
 * it would mean pinning the exact (non-interoperable) nonce derivation. */
static void test_dbls_bls_sign_gen(void) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    unsigned char key[32], msg[32], msg2[32], bad[32], badgen[48];
    unsigned char sig_a[80], sig_b[80], sig2[80];
    secp256k1_bls_scalar x, k_a, k_b, k2;
    secp256k1_bls_point gen_a, gen_b, P_a, P_b, R;
    int i;

    CHECK(secp256k1_bls_point_parse(&gen_a, secp256k1_bls_gen_a) == 1);
    CHECK(secp256k1_bls_point_parse(&gen_b, secp256k1_bls_gen_b) == 1);
    testrand256(key);
    key[0] = (key[0] & 0x3f) | 0x01;   /* 2^248 <= x < 2^254 < r */
    CHECK(secp256k1_bls_scalar_set_b32(&x, key) == 1);
    testrand256(msg);
    secp256k1_bls_point_mul(&P_a, &gen_a, &x);
    secp256k1_bls_point_mul(&P_b, &gen_b, &x);

    /* 1. gen_a: valid signature; R is a valid G1 point. */
    CHECK(dbls_bls_sign_gen(hash_ctx, sig_a, msg, 32, key, secp256k1_bls_gen_a) == 1);
    CHECK(secp256k1_bls_point_parse(&R, sig_a) == 1);
    CHECK(dbls_test_bls_verify(sig_a, msg, 32, &P_a, secp256k1_bls_gen_a));

    /* 2. gen_b: valid with P = x*gen_b. */
    CHECK(dbls_bls_sign_gen(hash_ctx, sig_b, msg, 32, key, secp256k1_bls_gen_b) == 1);
    CHECK(dbls_test_bls_verify(sig_b, msg, 32, &P_b, secp256k1_bls_gen_b));

    /* 3. Deterministic. */
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, key, secp256k1_bls_gen_b) == 1);
    CHECK(secp256k1_memcmp_var(sig2, sig_b, 80) == 0);

    /* 4. Nonce binds the generator: same (x, msg) under gen_a and gen_b uses different k. */
    dbls_test_bls_nonce(&k_a, sig_a, &P_a, &x, msg, 32);
    dbls_test_bls_nonce(&k_b, sig_b, &P_b, &x, msg, 32);
    CHECK(!bls_sc_eq(&k_a, &k_b));

    /* 5. Nonce binds the message. */
    memcpy(msg2, msg, 32); testrand_flip(msg2, 32);
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg2, 32, key, secp256k1_bls_gen_a) == 1);
    dbls_test_bls_nonce(&k2, sig2, &P_a, &x, msg2, 32);
    CHECK(!bls_sc_eq(&k_a, &k2));

    /* 6. x < 2^16 is rejected: 0, 1, 0xffff. */
    for (i = 0; i < 3; ++i) {
        memset(bad, 0, 32);
        if (i == 1) bad[31] = 1;
        if (i == 2) { bad[30] = 0xff; bad[31] = 0xff; }
        CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, bad, secp256k1_bls_gen_a) == 0);
    }

    /* 7. x = 2^16 is the first accepted value. */
    memset(bad, 0, 32); bad[29] = 1;
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, bad, secp256k1_bls_gen_a) == 1);
    CHECK(secp256k1_bls_scalar_set_b32(&k2, bad) == 1);
    secp256k1_bls_point_mul(&R, &gen_a, &k2);
    CHECK(dbls_test_bls_verify(sig2, msg, 32, &R, secp256k1_bls_gen_a));

    /* 8. x = r - 1 is accepted. */
    memcpy(bad, bls_fr_order_be, 32); bad[31] -= 1;
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, bad, secp256k1_bls_gen_a) == 1);

    /* 9. x = r and x = 2^256 - 1 are rejected. */
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, bls_fr_order_be, secp256k1_bls_gen_a) == 0);
    memset(bad, 0xff, 32);
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, bad, secp256k1_bls_gen_a) == 0);

    /* 10. Invalid generators: not a point, and the infinity encoding. */
    memset(badgen, 0xff, 48);
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, key, badgen) == 0);
    memset(badgen, 0, 48); badgen[0] = 0xc0;
    CHECK(dbls_bls_sign_gen(hash_ctx, sig2, msg, 32, key, badgen) == 0);

    /* 11. Wrong message is rejected. */
    CHECK(!dbls_test_bls_verify(sig_a, msg2, 32, &P_a, secp256k1_bls_gen_a));

    /* 12. Wrong pubkey is rejected: P under gen_b does not verify against gen_a. */
    CHECK(!dbls_test_bls_verify(sig_a, msg, 32, &P_b, secp256k1_bls_gen_a));

    /* 13. One flipped bit in R or in s is rejected (an invalid R/s counts as rejection). */
    memcpy(sig2, sig_a, 80); testrand_flip(sig2, 48);
    CHECK(!dbls_test_bls_verify(sig2, msg, 32, &P_a, secp256k1_bls_gen_a));
    memcpy(sig2, sig_a, 80); testrand_flip(sig2 + 48, 32);
    CHECK(!dbls_test_bls_verify(sig2, msg, 32, &P_a, secp256k1_bls_gen_a));
}

/* Random key in [2^(n-1), 2^n): fits n bits, top bit set (so >= 2^16 for n >= 17). */
static void dbls_test_key(unsigned char *key, size_t n_bits) {
    size_t i;
    testrand256(key);
    for (i = n_bits; i < 256; ++i) {
        key[31 - (i / 8)] &= (unsigned char)~(1 << (i % 8));
    }
    key[31 - ((n_bits - 1) / 8)] |= (unsigned char)(1 << ((n_bits - 1) % 8));
}

/* Structural checks on a proof from secp256k1_bls_dleag_prove (no verify yet):
 * pubkeys, both unblinding signatures, and sum(2^i * C[i]) == key * gen. */
static void dbls_test_check_proof(const unsigned char *proof, const unsigned char *key, size_t n_bits) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    unsigned char pk33[33], msg[32], pow2_b[32];
    size_t len = 33, i;
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    secp256k1_sha256 h;
    secp256k1_scalar x, pow2;
    secp256k1_bls_scalar xb, pow2b;
    secp256k1_gej acc_g, t, exp_g;
    secp256k1_ge ge;
    secp256k1_bls_point gen_a, P_bls, acc_b, cb, tb;
    const unsigned char *c_g = proof + 225;
    const unsigned char *c_b = proof + 225 + 33 * n_bits;

    /* 4. Pubkeys: secp key*G and G1 key*gen_a. */
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, key) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, pk33, &len, &pk, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(secp256k1_memcmp_var(proof, pk33, 33) == 0);
    CHECK(secp256k1_bls_point_parse(&gen_a, secp256k1_bls_gen_a) == 1);
    CHECK(secp256k1_bls_scalar_set_b32(&xb, key) == 1);
    secp256k1_bls_point_mul(&P_bls, &gen_a, &xb);
    CHECK(secp256k1_bls_point_parse(&tb, proof + 33) == 1);
    CHECK(bls_pt_eq(&tb, &P_bls));

    /* 5. ECDSA unblinding signature over SHA256("dleag message"), standard verifier. */
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(hash_ctx, &h, (const unsigned char *)dbls_sig_message, strlen(dbls_sig_message));
    secp256k1_sha256_finalize(hash_ctx, &h, msg);
    CHECK(secp256k1_ecdsa_signature_parse_compact(CTX, &sig, proof + 81) == 1);
    CHECK(secp256k1_ecdsa_verify(CTX, &sig, msg, &pk) == 1);

    /* 6. Schnorr-G1 unblinding signature under gen_a. */
    CHECK(dbls_test_bls_verify(proof + 145, msg, 32, &P_bls, secp256k1_bls_gen_a));

    /* 7. sum(2^i * C_G[i]) == key*G and sum(2^i * C_B[i]) == key*gen_a:
     *    the blinding factors cancel and each commitment carries the right bit. */
    secp256k1_gej_set_infinity(&acc_g);
    secp256k1_bls_point_set_infinity(&acc_b);
    for (i = 0; i < n_bits; ++i) {
        memset(pow2_b, 0, 32);
        pow2_b[31 - (i / 8)] = (unsigned char)(1 << (i % 8));
        secp256k1_scalar_set_b32(&pow2, pow2_b, NULL);
        CHECK(secp256k1_bls_scalar_set_b32(&pow2b, pow2_b) == 1);

        CHECK(secp256k1_eckey_pubkey_parse(&ge, c_g + 33 * i, 33) == 1);
        secp256k1_gej_set_ge(&t, &ge);
        secp256k1_ecmult(&t, &t, &pow2, &secp256k1_scalar_zero);
        secp256k1_gej_add_var(&acc_g, &acc_g, &t, NULL);

        CHECK(secp256k1_bls_point_parse(&cb, c_b + 48 * i) == 1);
        secp256k1_bls_point_mul(&tb, &cb, &pow2b);
        secp256k1_bls_point_add(&acc_b, &acc_b, &tb);
    }
    secp256k1_scalar_set_b32(&x, key, NULL);
    secp256k1_gej_set_ge(&exp_g, &secp256k1_ge_const_g);
    secp256k1_ecmult(&exp_g, &exp_g, &x, &secp256k1_scalar_zero);
    secp256k1_gej_neg(&exp_g, &exp_g);
    secp256k1_gej_add_var(&acc_g, &acc_g, &exp_g, NULL);
    CHECK(secp256k1_gej_is_infinity(&acc_g));
    CHECK(bls_pt_eq(&acc_b, &P_bls));
}

static void test_dbls_prove(void) {
    unsigned char key[32], key2[32], nonce[32], nonce2[32];
    unsigned char proof[52957], proof2[52957];
    size_t len, len2;
    size_t n_list[2];
    int t;

    n_list[0] = 252;
    n_list[1] = 64;
    for (t = 0; t < 2; ++t) {
        size_t n = n_list[t];
        dbls_test_key(key, n);
        testrand256(nonce);

        /* 1. Success; length matches dbls_proof_size. */
        len = sizeof(proof);
        CHECK(secp256k1_bls_dleag_prove(CTX, proof, &len, key, n, nonce) == 1);
        CHECK(len == dbls_proof_size(n));

        /* 2. Deterministic in (key, nonce). */
        len2 = sizeof(proof2);
        CHECK(secp256k1_bls_dleag_prove(CTX, proof2, &len2, key, n, nonce) == 1);
        CHECK(len2 == len && secp256k1_memcmp_var(proof, proof2, len) == 0);

        /* 3. Different nonce: different proof, same pubkeys. */
        memcpy(nonce2, nonce, 32); nonce2[0] ^= 1;
        len2 = sizeof(proof2);
        CHECK(secp256k1_bls_dleag_prove(CTX, proof2, &len2, key, n, nonce2) == 1);
        CHECK(secp256k1_memcmp_var(proof, proof2, 81) == 0);
        CHECK(secp256k1_memcmp_var(proof, proof2, len) != 0);

        /* 4-7. Pubkeys, unblinding signatures, commitment sums. */
        dbls_test_check_proof(proof, key, n);
    }

    /* 8. n_bits out of range. */
    len = sizeof(proof);
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_prove(CTX, proof, &len, key, 0, nonce));
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_prove(CTX, proof, &len, key, 253, nonce));

    /* 9. NULL arguments. */
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_prove(CTX, NULL, &len, key, 64, nonce));
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_prove(CTX, proof, NULL, key, 64, nonce));
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_prove(CTX, proof, &len, NULL, 64, nonce));
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_prove(CTX, proof, &len, key, 64, NULL));

    /* 10. Key with a bit set at position n_bits is rejected. */
    dbls_test_key(key2, 64);
    key2[31 - 8] |= 0x01;   /* bit 64 */
    len = sizeof(proof);
    CHECK(secp256k1_bls_dleag_prove(CTX, proof, &len, key2, 64, nonce) == 0);

    /* 11. key = 0 is rejected. */
    memset(key2, 0, 32);
    len = sizeof(proof);
    CHECK(secp256k1_bls_dleag_prove(CTX, proof, &len, key2, 64, nonce) == 0);

    /* 12. key = 0xffff (< 2^16) is rejected by the Schnorr-G1 step. */
    key2[30] = 0xff; key2[31] = 0xff;
    len = sizeof(proof);
    CHECK(secp256k1_bls_dleag_prove(CTX, proof, &len, key2, 64, nonce) == 0);

    /* 13. key = 2^16 with n_bits = 17 is the smallest working pair. */
    memset(key2, 0, 32); key2[29] = 0x01;
    len = sizeof(proof);
    CHECK(secp256k1_bls_dleag_prove(CTX, proof, &len, key2, 17, nonce) == 1);
    CHECK(len == dbls_proof_size(17));
    dbls_test_check_proof(proof, key2, 17);
}

/* The b >= 2^16 floor is not observable through verify (a modified b breaks
 * the ring anyway), so test the parser directly at its boundaries. */
static void test_dbls_bls_decode_check_scalar(void) {
    unsigned char b[32];
    secp256k1_bls_scalar sc, exp;

    memset(b, 0, 32);
    CHECK(dbls_bls_decode_check_scalar(&sc, b) == 0);              /* 0 */
    b[30] = 0xff; b[31] = 0xff;
    CHECK(dbls_bls_decode_check_scalar(&sc, b) == 0);              /* 2^16 - 1 */
    memset(b, 0, 32); b[29] = 0x01;
    CHECK(dbls_bls_decode_check_scalar(&sc, b) == 1);              /* 2^16 */
    CHECK(secp256k1_bls_scalar_set_b32(&exp, b) == 1);
    CHECK(bls_sc_eq(&sc, &exp));
    memcpy(b, bls_fr_order_be, 32); b[31] -= 1;
    CHECK(dbls_bls_decode_check_scalar(&sc, b) == 1);              /* r - 1 */
    CHECK(dbls_bls_decode_check_scalar(&sc, bls_fr_order_be) == 0); /* r */
    memset(b, 0xff, 32);
    CHECK(dbls_bls_decode_check_scalar(&sc, b) == 0);              /* 2^256 - 1 */
}

/* Proof layout offsets for n_bits. */
#define DBLS_OFS_CG(i)     (225 + 33 * (i))
#define DBLS_OFS_CB(n, i)  (225 + 33 * (n) + 48 * (i))
#define DBLS_OFS_JH(n)     (225 + 81 * (n))
#define DBLS_OFS_A0(n, i)  (225 + 81 * (n) + 64 + 32 * (i))
#define DBLS_OFS_A1(n, i)  (DBLS_OFS_A0(n, i) + 32 * (n))
#define DBLS_OFS_B0(n, i)  (DBLS_OFS_A1(n, i) + 32 * (n))
#define DBLS_OFS_B1(n, i)  (DBLS_OFS_B0(n, i) + 32 * (n))

static void dbls_test_make_proof(unsigned char *proof, size_t *len, unsigned char *key, size_t n_bits) {
    unsigned char nonce[32];
    dbls_test_key(key, n_bits);
    testrand256(nonce);
    *len = dbls_proof_size(n_bits);
    CHECK(secp256k1_bls_dleag_prove(CTX, proof, len, key, n_bits, nonce) == 1);
}

static void dbls_test_load_cg(secp256k1_ge *ge, const unsigned char *proof, size_t i) {
    CHECK(secp256k1_eckey_pubkey_parse(ge, proof + DBLS_OFS_CG(i), 33) == 1);
}

static void dbls_test_store_cg(unsigned char *proof, size_t i, const secp256k1_gej *pj) {
    secp256k1_gej tj = *pj;
    secp256k1_ge ge;
    CHECK(!secp256k1_gej_is_infinity(&tj));
    secp256k1_ge_set_gej(&ge, &tj);
    secp256k1_fe_normalize_var(&ge.x);
    secp256k1_fe_normalize_var(&ge.y);
    secp256k1_eckey_pubkey_serialize33(&ge, proof + DBLS_OFS_CG(i));
}

/* Malicious rewrite that keeps sum(2^i * C_G[i]) unchanged: set C_G[0] = T
 * and compensate in C_G[1] with D = (T - C_G[0]) / 2, i.e. C_G[1] -= D. */
static void dbls_test_rebalance_cg(unsigned char *proof, const secp256k1_gej *T) {
    secp256k1_ge c0, c1;
    secp256k1_gej d, t;
    secp256k1_scalar two, inv2;

    dbls_test_load_cg(&c0, proof, 0);
    dbls_test_load_cg(&c1, proof, 1);
    secp256k1_ge_neg(&c0, &c0);
    secp256k1_gej_add_ge_var(&d, T, &c0, NULL);               /* T - C_G[0] */
    secp256k1_scalar_set_int(&two, 2);
    secp256k1_scalar_inverse_var(&inv2, &two);
    secp256k1_ecmult(&d, &d, &inv2, &secp256k1_scalar_zero);  /* D */
    secp256k1_gej_neg(&d, &d);
    secp256k1_gej_add_ge_var(&t, &d, &c1, NULL);              /* C_G[1] - D */
    dbls_test_store_cg(proof, 0, T);
    dbls_test_store_cg(proof, 1, &t);
}

/* Recompute the verifier's preimage hash over (possibly modified) proof bytes. */
static void dbls_test_preimage(unsigned char *out32, const unsigned char *proof, size_t n_bits) {
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
    secp256k1_sha256 h;
    size_t i;
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(hash_ctx, &h, proof, 33 + 48);
    for (i = 0; i < n_bits; ++i) {
        secp256k1_sha256_write(hash_ctx, &h, proof + DBLS_OFS_CG(i), 33);
        secp256k1_sha256_write(hash_ctx, &h, proof + DBLS_OFS_CB(n_bits, i), 48);
    }
    secp256k1_sha256_finalize(hash_ctx, &h, out32);
}

static void test_dbls_verify(void) {
    static unsigned char proof[52957], p2[52957];
    unsigned char key[32];
    size_t len, n, i, t;
    size_t n_list[3];
    secp256k1_gej T;
    secp256k1_ge H;
    secp256k1_scalar c, e0, a;

    n_list[0] = 252; n_list[1] = 64; n_list[2] = 17;

    /* V1. Honest proofs verify. */
    for (t = 0; t < 3; ++t) {
        dbls_test_make_proof(proof, &len, key, n_list[t]);
        CHECK(secp256k1_bls_dleag_verify(CTX, proof, len, n_list[t]) == 1);
    }

    n = 64;
    dbls_test_make_proof(proof, &len, key, n);

    /* V2. Wrong n_bits / wrong length. */
    CHECK(secp256k1_bls_dleag_verify(CTX, proof, len, n - 1) == 0);
    CHECK(secp256k1_bls_dleag_verify(CTX, proof, len, n + 1) == 0);
    CHECK(secp256k1_bls_dleag_verify(CTX, proof, len - 1, n) == 0);
    CHECK(secp256k1_bls_dleag_verify(CTX, proof, len + 1, n) == 0);

    /* V3. One flipped bit in each region of the proof is rejected. */
    {
        size_t reg[11][2];
        reg[0][0] = 0;                     reg[0][1] = 33;        /* secp pubkey */
        reg[1][0] = 33;                    reg[1][1] = 48;        /* G1 pubkey */
        reg[2][0] = 81;                    reg[2][1] = 64;        /* ECDSA */
        reg[3][0] = 145;                   reg[3][1] = 80;        /* Schnorr-G1 */
        reg[4][0] = DBLS_OFS_CG(0);        reg[4][1] = 33 * n;    /* C_G */
        reg[5][0] = DBLS_OFS_CB(n, 0);     reg[5][1] = 48 * n;    /* C_B */
        reg[6][0] = DBLS_OFS_JH(n);        reg[6][1] = 64;        /* J_hash, K_hash */
        reg[7][0] = DBLS_OFS_A0(n, 0);     reg[7][1] = 32 * n;    /* a0 */
        reg[8][0] = DBLS_OFS_A1(n, 0);     reg[8][1] = 32 * n;    /* a1 */
        reg[9][0] = DBLS_OFS_B0(n, 0);     reg[9][1] = 32 * n;    /* b0 */
        reg[10][0] = DBLS_OFS_B1(n, 0);    reg[10][1] = 32 * n;   /* b1 */
        CHECK(reg[10][0] + reg[10][1] == len);
        for (i = 0; i < 11; ++i) {
            memcpy(p2, proof, len);
            testrand_flip(p2 + reg[i][0], reg[i][1]);
            CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);
        }
    }

    /* V4. Non-canonical / out-of-range scalars are rejected. */
    memcpy(p2, proof, len); memcpy(p2 + DBLS_OFS_A0(n, 3), dbls_secp_order_be, 32);
    CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);                      /* a = n */
    memcpy(p2, proof, len); memset(p2 + DBLS_OFS_A1(n, 3), 0, 32);
    CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);                      /* a = 0 */
    memcpy(p2, proof, len); memcpy(p2 + DBLS_OFS_B0(n, 3), bls_fr_order_be, 32);
    CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);                      /* b = r */
    memcpy(p2, proof, len); memset(p2 + DBLS_OFS_B1(n, 3), 0, 32); p2[DBLS_OFS_B1(n, 3) + 30] = 0xff;
    CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);                      /* b < 2^16 */

    /* V5. Illegal arguments. */
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_verify(CTX, NULL, len, n));
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_verify(CTX, proof, len, 0));
    CHECK_ILLEGAL(CTX, secp256k1_bls_dleag_verify(CTX, proof, len, 253));

    secp256k1_generator_load(&H, &secp256k1_generator_const_h);

    /* V6. Crafted J = infinity (bit 0, slot 0): C_G[0] = c*H, a0[0] = e0*c, so
     *     J = a0*H - e0*C_G[0] = 0. Must return 0, not abort. */
    {
        const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
        unsigned char pre[32], h[32];
        memcpy(p2, proof, len);
        testutil_random_scalar_order(&c);
        secp256k1_gej_set_ge(&T, &H);
        secp256k1_ecmult(&T, &T, &c, &secp256k1_scalar_zero);
        dbls_test_rebalance_cg(p2, &T);
        dbls_test_preimage(pre, p2, n);
        dbls_dleag_hash(h, hash_ctx, pre, p2 + DBLS_OFS_JH(n), 32, p2 + DBLS_OFS_JH(n) + 32, 32, 0, 0);
        CHECK(dbls_hash_sc_secp256k1(&e0, hash_ctx, h) == 1);
        secp256k1_scalar_mul(&a, &e0, &c);
        secp256k1_scalar_get_b32(p2 + DBLS_OFS_A0(n, 0), &a);
        CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);
    }

    /* V7. Crafted C_G[0] = G: in slot 1, C_G[0] - G = infinity is added as a
     *     group element. Must return 0, not abort. */
    memcpy(p2, proof, len);
    secp256k1_gej_set_ge(&T, &secp256k1_ge_const_g);
    dbls_test_rebalance_cg(p2, &T);
    CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);

    /* V8. Crafted sum(2^i * C_G[i]) = infinity: C_G[0] -= P_secp. Must return 0, not abort. */
    {
        secp256k1_ge c0, P;
        secp256k1_gej acc;
        memcpy(p2, proof, len);
        dbls_test_load_cg(&c0, p2, 0);
        CHECK(secp256k1_eckey_pubkey_parse(&P, p2, 33) == 1);
        secp256k1_ge_neg(&P, &P);
        secp256k1_gej_set_ge(&acc, &c0);
        secp256k1_gej_add_ge_var(&acc, &acc, &P, NULL);
        dbls_test_store_cg(p2, 0, &acc);
        CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);
    }

    /* V9. Crafted ECDSA unblinding signature with r = -m/x: the verifier's
     *     R = (m/s)*G + (r/s)*P is infinity. Must return 0, not abort. */
    {
        const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(CTX);
        secp256k1_sha256 hs;
        unsigned char m32[32];
        secp256k1_scalar m, x, r;
        secp256k1_sha256_initialize(&hs);
        secp256k1_sha256_write(hash_ctx, &hs, (const unsigned char *)dbls_sig_message, strlen(dbls_sig_message));
        secp256k1_sha256_finalize(hash_ctx, &hs, m32);
        secp256k1_scalar_set_b32(&m, m32, NULL);
        secp256k1_scalar_set_b32(&x, key, NULL);
        secp256k1_scalar_inverse_var(&r, &x);
        secp256k1_scalar_mul(&r, &r, &m);
        secp256k1_scalar_negate(&r, &r);
        memcpy(p2, proof, len);
        secp256k1_scalar_get_b32(p2 + 81, &r);
        memset(p2 + 81 + 32, 0, 32); p2[81 + 63] = 1;              /* s = 1 (low-s) */
        CHECK(secp256k1_bls_dleag_verify(CTX, p2, len, n) == 0);
    }
}

static void test_dbls_verify_bls_point(void) {
    /* 2*G, computed independently (pure Python affine arithmetic). */
    static const unsigned char g2[48] = {
        0xa5,0x72,0xcb,0xea,0x90,0x4d,0x67,0x46,0x88,0x08,0xc8,0xeb,0x50,0xa9,0x45,0x0c,
        0x97,0x21,0xdb,0x30,0x91,0x28,0x01,0x25,0x43,0x90,0x2d,0x0a,0xc3,0x58,0xa6,0x2a,
        0xe2,0x8f,0x75,0xbb,0x8f,0x1c,0x7c,0x42,0xc3,0x9a,0x8c,0x55,0x29,0xbf,0x0f,0x4e
    };
    static unsigned char proof[52957];
    unsigned char key[32], p[48];
    size_t len;

    /* Valid: G, 2G, and the G1 pubkey embedded in a real proof. */
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, secp256k1_bls_gen_a) == 1);
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, g2) == 1);
    dbls_test_make_proof(proof, &len, key, 64);
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, proof + 33) == 1);

    /* Infinity. */
    memset(p, 0, 48); p[0] = 0xc0;
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, p) == 0);
    /* Garbage. */
    memset(p, 0xff, 48);
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, p) == 0);
    /* G without the compression flag. */
    memcpy(p, secp256k1_bls_gen_a, 48); p[0] &= 0x7f;
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, p) == 0);
    /* (0, +-2): on the curve (0^3 + 4 = 2^2) but of order 3, not in the subgroup. */
    memset(p, 0, 48); p[0] = 0x80;
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, p) == 0);
    p[0] = 0xa0;
    CHECK(secp256k1_bls_dleag_verify_bls_point(CTX, p) == 0);
}

/* --- Test registry --- */
static const struct tf_test_entry tests_dleag_bls[] = {
    CASE1(test_dbls_proof_size),
    CASE1(test_dbls_dleag_hash),
    CASE1(test_dbls_hash_to_scalar),
    CASE1(test_dbls_get_sc),
    CASE1(test_dbls_raise_point_encode),
    CASE1(test_dbls_ecdsa_sign_gen),
    CASE1(test_dbls_bls_sign_gen),
    CASE1(test_dbls_prove),
    CASE1(test_dbls_bls_decode_check_scalar),
    CASE1(test_dbls_verify),
    CASE1(test_dbls_verify_bls_point),
};

#endif
