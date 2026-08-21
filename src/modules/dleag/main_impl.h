/**********************************************************************
 * Copyright (c) 2020-2024 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_DLEAG_MAIN
#define SECP256K1_DLEAG_MAIN

#include "../../../include/secp256k1_dleag.h"

typedef uint8_t ed25519_scalar_t[32];
typedef uint8_t ed25519_point_t[32];
static const char *dleag_sig_message = "dleag message";


static int secp256k1_ecdsa_sig_sign_gen(secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid, const secp256k1_gej *genj) {
    unsigned char b[32];
    secp256k1_gej rp;
    secp256k1_ge r;
    secp256k1_scalar n;

    int overflow = 0;
    int high;
    int r_valid;
    int s_valid;

    secp256k1_scalar_clear(&n);
    secp256k1_ecmult(&rp, genj, nonce, &n);
    /* secp256k1_ecmult_gen(ctx, &rp, nonce); */
    secp256k1_ge_set_gej(&r, &rp);
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_normalize(&r.y);
    secp256k1_fe_get_b32(b, &r.x);
    secp256k1_scalar_set_b32(sigr, b, &overflow);
    if (recid) {
        /* The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
         * of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
         */
        *recid = (overflow << 1) | secp256k1_fe_is_odd(&r.y);
    }
    secp256k1_scalar_mul(&n, sigr, seckey);
    secp256k1_scalar_add(&n, &n, message);
    secp256k1_scalar_inverse(sigs, nonce);
    secp256k1_scalar_mul(sigs, sigs, &n);
    secp256k1_scalar_clear(&n);
    secp256k1_gej_clear(&rp);
    secp256k1_ge_clear(&r);
    high = secp256k1_scalar_is_high(sigs);
    secp256k1_scalar_cond_negate(sigs, high);
    if (recid) {
        *recid ^= high;
    }
    /* P.x = order is on the curve, so technically sig->r could end up being zero, which would be an invalid signature.
     * This is cryptographically unreachable as hitting it requires finding the discrete log of P.x = N.
     * Bitwise on purpose below: both sides must be evaluated.
     */
    r_valid = !secp256k1_scalar_is_zero(sigr);
    s_valid = !secp256k1_scalar_is_zero(sigs);
    return r_valid & s_valid;
}

static int secp256k1_ecdsa_sign_inner_gen(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, int* recid, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata, const secp256k1_gej *genj, const unsigned char *gen33) {
    secp256k1_scalar sec, non, msg;
    int ret = 0;
    int is_sec_valid;
    unsigned char nonce32[32];
    unsigned char nonce_msg[32];
    secp256k1_sha256 h;
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(ctx);
    unsigned int count = 0;
    /* Tagged so a signature over a custom generator can never share a nonce
       with a plain-ECDSA signature for the same (key, message). */
    const char *algo16 = "DLEAGECDSA/nonce";
    /* Default initialization here is important so we won't pass uninit values to the cmov in the end */
    *r = secp256k1_scalar_zero;
    *s = secp256k1_scalar_zero;
    if (recid) {
        *recid = 0;
    }
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    /* Fail if the secret key is invalid. */
    is_sec_valid = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, !is_sec_valid);
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    /* Only the nonce derivation binds the generator; the signed message stays
       msg32. noncedata is left free for the caller. */
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(hash_ctx, &h, msg32, 32);
    secp256k1_sha256_write(hash_ctx, &h, gen33, 33);
    secp256k1_sha256_finalize(hash_ctx, &h, nonce_msg);
    while (1) {
        int is_nonce_valid;
        ret = !!noncefp(nonce32, nonce_msg, seckey, (unsigned char*)algo16, (void*)noncedata, count);
        if (!ret) {
            break;
        }
        is_nonce_valid = secp256k1_scalar_set_b32_seckey(&non, nonce32);
        /* The nonce is still secret here, but it being invalid is is less likely than 1:2^255. */
        secp256k1_declassify(ctx, &is_nonce_valid, sizeof(is_nonce_valid));
        if (is_nonce_valid) {
            ret = secp256k1_ecdsa_sig_sign_gen(r, s, &sec, &msg, &non, recid, genj);
            /* The final signature is no longer a secret, nor is the fact that we were successful or not. */
            secp256k1_declassify(ctx, &ret, sizeof(ret));
            if (ret) {
                break;
            }
        }
        count++;
    }
    /* We don't want to declassify is_sec_valid and therefore the range of
     * seckey. As a result is_sec_valid is included in ret only after ret was
     * used as a branching variable. */
    ret &= is_sec_valid;
    memset(nonce32, 0, 32);
    secp256k1_scalar_clear(&msg);
    secp256k1_scalar_clear(&non);
    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_cmov(r, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_cmov(s, &secp256k1_scalar_zero, !ret);
    if (recid) {
        const int zero = 0;
        secp256k1_int_cmov(recid, &zero, !ret);
    }
    return ret;
}

int secp256k1_ecdsa_sign_recoverable_gen(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata, const secp256k1_generator *gen) {
    secp256k1_scalar r, s;
    secp256k1_ge ge;
    secp256k1_gej genj;
    unsigned char gen33[33];
    int ret, recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(gen != NULL);

    if (!secp256k1_generator_serialize(ctx, gen33, gen)) {
        return 0;
    }
    secp256k1_generator_load(&ge, gen);
    secp256k1_gej_set_ge(&genj, &ge);

    ret = secp256k1_ecdsa_sign_inner_gen(ctx, &r, &s, &recid, msg32, seckey, noncefp, noncedata, &genj, gen33);
    secp256k1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    return ret;
}

static int secp256k1_ecdsa_sig_verify_gen(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message, const secp256k1_gej *genj) {
    unsigned char c[32];
    secp256k1_scalar sn, u1, u2;
    secp256k1_fe xr;
    secp256k1_gej pubkeyj;
    secp256k1_gej pr, qr;
    secp256k1_ge ge;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs)) {
        return 0;
    }

    secp256k1_scalar_inverse_var(&sn, sigs);
    secp256k1_scalar_mul(&u1, &sn, message);
    secp256k1_scalar_mul(&u2, &sn, sigr);
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    /*secp256k1_ecmult(ctx, &pr, &pubkeyj, &u2, &u1);*/
    secp256k1_ecmult(&pr, &pubkeyj, &u2, &secp256k1_scalar_zero);
    secp256k1_ecmult(&qr, genj, &u1, &secp256k1_scalar_zero);
    secp256k1_ge_set_gej(&ge, &qr);
    secp256k1_gej_add_ge(&pr, &pr, &ge);

    secp256k1_scalar_get_b32(c, sigr);
    secp256k1_fe_set_b32_mod(&xr, c);

    /** We now have the recomputed R point in pr, and its claimed x coordinate (modulo n)
     *  in xr. Naively, we would extract the x coordinate from pr (requiring a inversion modulo p),
     *  compute the remainder modulo n, and compare it to xr. However:
     *
     *        xr == X(pr) mod n
     *    <=> exists h. (xr + h * n < p && xr + h * n == X(pr))
     *    [Since 2 * n > p, h can only be 0 or 1]
     *    <=> (xr == X(pr)) || (xr + n < p && xr + n == X(pr))
     *    [In Jacobian coordinates, X(pr) is pr.x / pr.z^2 mod p]
     *    <=> (xr == pr.x / pr.z^2 mod p) || (xr + n < p && xr + n == pr.x / pr.z^2 mod p)
     *    [Multiplying both sides of the equations by pr.z^2 mod p]
     *    <=> (xr * pr.z^2 mod p == pr.x) || (xr + n < p && (xr + n) * pr.z^2 mod p == pr.x)
     *
     *  Thus, we can avoid the inversion, but we have to check both cases separately.
     *  secp256k1_gej_eq_x implements the (xr * pr.z^2 mod p == pr.x) test.
     */
    if (secp256k1_gej_eq_x_var(&xr, &pr)) {
        /* xr * pr.z^2 mod p == pr.x, so the signature is valid. */
        return 1;
    }
    if (secp256k1_fe_cmp_var(&xr, &secp256k1_ecdsa_const_p_minus_order) >= 0) {
        /* xr + n >= p, so we can skip testing the second case. */
        return 0;
    }
    secp256k1_fe_add(&xr, &secp256k1_ecdsa_const_order_as_fe);
    if (secp256k1_gej_eq_x_var(&xr, &pr)) {
        /* (xr + n) * pr.z^2 mod p == pr.x, so the signature is valid. */
        return 1;
    }
    return 0;
}

int secp256k1_ecdsa_verify_gen(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey, const secp256k1_generator *gen) {
    secp256k1_ge q;
    secp256k1_scalar r, s;
    secp256k1_scalar m;
    secp256k1_ge ge;
    secp256k1_gej genj;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(gen != NULL);

    secp256k1_generator_load(&ge, gen);
    secp256k1_gej_set_ge(&genj, &ge);

    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!secp256k1_scalar_is_high(&s) &&
            secp256k1_pubkey_load(ctx, &q, pubkey) &&
            secp256k1_ecdsa_sig_verify_gen(&r, &s, &q, &m, &genj));
}


SECP256K1_API int ed25519_sign_gen(
    unsigned char *sig,
    const unsigned char *msg,
    size_t mlen,
    const unsigned char *seckey,
    const unsigned char *gen) {
    ge25519_p3 genj, P, R;
    crypto_hash_sha512_state hs;
    unsigned char sc[32], az[64], nonce[64], hram[64];

    if (!ed25519_less_than_l_be(seckey) ||
        sodium_is_zero(seckey, 30)) { /* skip lsb to raise min value */
        return 0;
    }
    reverse32(sc, seckey);

    if (ge25519_frombytes(&genj, gen) != 0) {
        return 0;
    }

    ge25519_scalarmult(&P, sc, &genj);

    crypto_hash_sha512(az, sc, 32);
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, az + 32, 32);
    /* Bind the generator: without it, two signatures over the same (key,
       message) under different generators share a nonce and s1 - s2 =
       (h1 - h2) * sc recovers the key. */
    crypto_hash_sha512_update(&hs, gen, 32);
    crypto_hash_sha512_update(&hs, msg, mlen);
    crypto_hash_sha512_final(&hs, nonce);

    sc25519_reduce(nonce);
    ge25519_scalarmult(&R, nonce, &genj);
    ge25519_p3_tobytes(sig, &R);

    ge25519_p3_tobytes(sig + 32, &P); /* temporarily store pk for msg hash */

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, sig, 64);
    crypto_hash_sha512_update(&hs, msg, mlen);
    crypto_hash_sha512_final(&hs, hram);
    sc25519_reduce(hram);

    sc25519_muladd(sig + 32, hram, sc, nonce);

    sodium_memzero(sc, sizeof sc);
    sodium_memzero(az, sizeof az);
    sodium_memzero(nonce, sizeof nonce);

    return 1;
}

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int ed25519_verify_gen(
    const unsigned char *sig,
    const unsigned char *msg,
    size_t mlen,
    const unsigned char *pubkey,
    const unsigned char *gen) {
    crypto_hash_sha512_state hs;
    ge25519_p3 genj, P, R, Q;
    unsigned char rcheck[32], hram[64];
    ge25519_p1p1   r_p1p1;
    ge25519_cached q_cached;

    if ((sig[63] & 240) &&
        sc25519_is_canonical(sig + 32) == 0) {
        return 0;
    }
    if (ge25519_has_small_order(sig) != 0) {
        return 0;
    }
    if (ge25519_is_canonical(pubkey) == 0 ||
        ge25519_has_small_order(pubkey) != 0) {
        return 0;
    }
    if (ge25519_frombytes(&genj, gen) != 0 ||
        ge25519_frombytes_negate_vartime(&P, pubkey) != 0) {
        return 0;
    }

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, sig, 32);
    crypto_hash_sha512_update(&hs, pubkey, 32);
    crypto_hash_sha512_update(&hs, msg, mlen);
    crypto_hash_sha512_final(&hs, hram);
    sc25519_reduce(hram);
    ge25519_scalarmult(&R, hram, &P);
    ge25519_scalarmult(&Q, sig + 32, &genj);

    ge25519_p3_to_cached(&q_cached, &Q);
    ge25519_add(&r_p1p1, &R, &q_cached);
    ge25519_p1p1_to_p3(&R, &r_p1p1);

    ge25519_p3_tobytes(rcheck, &R);

    return sodium_memcmp(sig, rcheck, 32) == 0 ? 1 : 0;
}


size_t secp256k1_dleag_size(size_t n_bits) {
    return 65 +         /* 2 pubkeys */
           64 + 64 +    /* 2 signatures */
           64 + 193 * n_bits;
}

SECP256K1_INLINE static int get_sc_secp256k1(secp256k1_scalar *sc, const secp256k1_hash_ctx *hash_ctx, secp256k1_rfc6979_hmac_sha256 *rng) {
    int overflow = 0;
    unsigned char tmp[32];
    do {
        secp256k1_rfc6979_hmac_sha256_generate(hash_ctx, rng, tmp, 32);
        secp256k1_scalar_set_b32(sc, tmp, &overflow);
    } while (overflow || secp256k1_scalar_is_zero(sc));
    return 1;
}

SECP256K1_INLINE static int get_sc_ed25519(unsigned char *out, const secp256k1_hash_ctx *hash_ctx, secp256k1_rfc6979_hmac_sha256 *rng) {
    do {
        secp256k1_rfc6979_hmac_sha256_generate(hash_ctx, rng, out, 32);
        out[0] &= 0x1f; /* Clear top 3 bits */
    } while (0 == ed25519_less_than_l_be(out));
    return 1;
}

SECP256K1_INLINE static int hash_sc_secp256k1(secp256k1_scalar *sc, const secp256k1_hash_ctx *hash_ctx, const unsigned char *bytes) {
    size_t i;
    int overflow;
    secp256k1_sha256 sha256_en;
    unsigned char tmp[32];
    memcpy(tmp, bytes, 32);
    for (i = 0; i < 1000; ++i) {
        secp256k1_scalar_set_b32(sc, tmp, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(sc)) {
            return 1;
        }
        secp256k1_sha256_initialize(&sha256_en);
        secp256k1_sha256_write(hash_ctx, &sha256_en, tmp, 32);
        secp256k1_sha256_finalize(hash_ctx, &sha256_en, tmp);
    }
    return 0;
}

SECP256K1_INLINE static int hash_sc_ed25519(unsigned char *out, const secp256k1_hash_ctx *hash_ctx, const unsigned char *bytes) {
    size_t i;
    secp256k1_sha256 sha256_en;
    memcpy(out, bytes, 32);
    for (i = 0; i < 1000; ++i) {
        out[0] &= 0x1f; /* Clear top 3 bits */
        if (ed25519_less_than_l_be(out)) {
            return 1;
        }
        secp256k1_sha256_initialize(&sha256_en);
        secp256k1_sha256_write(hash_ctx, &sha256_en, out, 32);
        secp256k1_sha256_finalize(hash_ctx, &sha256_en, out);
    }
    return 0;
}

SECP256K1_INLINE static void secp256k1_ge_neg_inplace(secp256k1_ge *r) {
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

SECP256K1_INLINE static int secp256k1_raise_point_encode(const secp256k1_context *ctx, unsigned char *out, secp256k1_gej *P, const secp256k1_scalar *ss) {
    secp256k1_gej ptj;

    secp256k1_ecmult(&ptj, P, ss, &secp256k1_scalar_zero);
    return secp256k1_gej_serialize(ctx, out, &ptj);
}

SECP256K1_INLINE static int ed25519_decode_check_point(ge25519_p3 *P, const unsigned char *p) {
    /* From crypto_core_ed25519_is_valid_point() */
    if (ge25519_is_canonical(p) == 0 ||
        ge25519_has_small_order(p) != 0 ||
        ge25519_frombytes(P, p) != 0 ||    /* ge25519_frombytes fails to load infinity points */
        ge25519_is_on_curve(P) == 0 ||
        ge25519_is_on_main_subgroup(P) == 0) {
        return 0;
    }
    return 1;
}

SECP256K1_INLINE static int ed25519_decode_check_scalar(unsigned char *sc, const unsigned char *p) {
    /* Input BE, output LE */
    if (!ed25519_less_than_l_be(p) ||
        sodium_is_zero(p, 30)) { /* skip lsb to raise min value */
        return 0;
    }
    reverse32(sc, p);
    return 1;
}

#ifdef SECP256K1_BIG_ENDIAN
#define BE32(x) (x)
#else
#define BE32(p) ((((p) & 0xFF) << 24) | (((p) & 0xFF00) << 8) | (((p) & 0xFF0000) >> 8) | (((p) & 0xFF000000) >> 24))
#endif

SECP256K1_INLINE static void dleag_hash(
    unsigned char *out,
    const secp256k1_hash_ctx *hash_ctx,
    const unsigned char *preimage,
    const unsigned char *bJ, size_t len_j,
    const unsigned char *bK,
    size_t i, size_t j) {
    uint32_t ring = BE32((uint32_t)i);
    uint32_t epos = BE32((uint32_t)j);
    secp256k1_sha256 sha256_en;
    secp256k1_sha256_initialize(&sha256_en);
    secp256k1_sha256_write(hash_ctx, &sha256_en, preimage, 32);
    secp256k1_sha256_write(hash_ctx, &sha256_en, bJ, len_j);
    secp256k1_sha256_write(hash_ctx, &sha256_en, bK, 32);
    secp256k1_sha256_write(hash_ctx, &sha256_en, (unsigned char*)&ring, 4);
    secp256k1_sha256_write(hash_ctx, &sha256_en, (unsigned char*)&epos, 4);
    secp256k1_sha256_finalize(hash_ctx, &sha256_en, out);
}

#undef BE32

int secp256k1_dleag_prove(
    const secp256k1_context *ctx,
    unsigned char *proof_out,
    size_t *proof_len,
    const unsigned char *key,
    size_t n_bits,
    const unsigned char *nonce,
    const secp256k1_generator *gen_s_a,
    const secp256k1_generator *gen_s_b,
    const unsigned char *gen_e_a,
    const unsigned char *gen_e_b) {
    size_t i, j;
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char rngseed[32 + 33 + 32];
    unsigned char key_r[32];
    unsigned char tmp_bytes[33];
    unsigned char preimage_hash[32], J_hash[32], K_hash[32];
    secp256k1_gej gej_gen_s_a, gej_gen_s_b;
    ge25519_p3 gej_gen_e_a, gej_gen_e_b;
    secp256k1_ge s_pt;
    secp256k1_scalar ss;
    int overflow = 0;
    secp256k1_sha256 hash_state, hash_J, hash_K;
    secp256k1_scalar r[256];
    secp256k1_scalar sum_r;
    secp256k1_scalar sv1, sv2;
    ed25519_scalar_t s[256];
    ed25519_scalar_t sum_s;
    ed25519_scalar_t ev1, ev2;
    secp256k1_gej C_G[256];
    secp256k1_gej spj1, spj2;
    const secp256k1_scalar *ps;
    const unsigned char *pe;
    ge25519_p3 C_B[256];
    ge25519_p3 ep1, ep2;
    ge25519_p1p1   r_p1p1;
    ge25519_cached q_cached;
    secp256k1_scalar sc_j[256];
    ed25519_scalar_t sc_k[256];
    secp256k1_scalar sc_a[256 * 2];
    ed25519_scalar_t sc_b[256 * 2];
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(ctx);

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof_out != NULL);
    ARG_CHECK(proof_len != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(gen_s_a != NULL);
    ARG_CHECK(gen_s_b != NULL);
    ARG_CHECK(gen_e_a != NULL);
    ARG_CHECK(gen_e_b != NULL);

    if (*proof_len < secp256k1_dleag_size(n_bits)) {
        return 0;
    }

    secp256k1_generator_load(&s_pt, gen_s_a);
    secp256k1_gej_set_ge(&gej_gen_s_a, &s_pt);
    secp256k1_generator_load(&s_pt, gen_s_b);
    secp256k1_gej_set_ge(&gej_gen_s_b, &s_pt);

    if (ge25519_frombytes(&gej_gen_e_a, gen_e_a) != 0 ||
        ge25519_frombytes(&gej_gen_e_b, gen_e_b) != 0) {
        return 0;
    }

    /* s_pk = GSA * key */
    secp256k1_scalar_set_b32(&ss, key, &overflow);
    if (overflow ||
        secp256k1_scalar_is_zero(&ss)) {
        return 0;
    }
    if (!secp256k1_raise_point_encode(ctx, proof_out, &gej_gen_s_a, &ss)) {
        return 0;
    }
    secp256k1_scalar_clear(&ss);

    /* e_pk = GEA * key */
    reverse32(key_r, key); /* ed25519 code expects LE data */
    if (0 != crypto_scalarmult_ed25519_noclamp(proof_out + 33, key_r, gen_e_a)) {
        return 0;
    }
    sodium_memzero(key_r, 32);

    /* Include signatures to prove points are unblinded */
    {
    secp256k1_ecdsa_recoverable_signature sig;
    int rec = -1;
    secp256k1_sha256_initialize(&hash_state);
    secp256k1_sha256_write(hash_ctx, &hash_state, (const unsigned char*) dleag_sig_message, strlen(dleag_sig_message));
    secp256k1_sha256_finalize(hash_ctx, &hash_state, preimage_hash);
    if (!secp256k1_ecdsa_sign_recoverable_gen(ctx, &sig, preimage_hash, key, NULL, NULL, gen_s_a) ||
        !secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, proof_out + 65, &rec, &sig)) {
        return 0;
    }
    if (!ed25519_sign_gen(proof_out + 65 + 64, preimage_hash, 32, key, gen_e_a)) {
        return 0;
    }
    }

    /* Seed csprng */
    memcpy(rngseed, nonce, 32);
    memcpy(rngseed + 32, proof_out, 33 + 32);
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng, rngseed, 32 + 33 + 32);

    /* Set the last r and s so they sum to 0 when weighted by bit position */
    secp256k1_scalar_set_int(&sum_r, 0);
    memset(sum_s, 0, 32);
    for (i = 0; i < n_bits-1; ++i) {
        if (!get_sc_secp256k1(&r[i], hash_ctx, &rng) ||
            !get_sc_ed25519(s[i], hash_ctx, &rng)) {
            return 0;
        }

        reverse32(key_r, s[i]);
        memcpy(s[i], key_r, 32);

        secp256k1_scalar_cmov(&sv1, &r[i], 1);
        if (i > 0) {
            secp256k1_scalar_clear(&ss);
            secp256k1_scalar_cadd_bit(&ss, i, 1);
            secp256k1_scalar_mul(&sv1, &sv1, &ss);

            memset(tmp_bytes, 0, 32);
            tmp_bytes[(i / 8)] |= (1 << (i % 8));
            crypto_core_ed25519_scalar_mul(key_r, key_r, tmp_bytes);
        }
        secp256k1_scalar_add(&sum_r, &sum_r, &sv1);
        crypto_core_ed25519_scalar_add(sum_s, key_r, sum_s);
    }

    /* r[n - 1] =  -r * inverse_mod(2^(n-1)) */
    secp256k1_scalar_negate(&sv1, &sum_r);
    memset(tmp_bytes, 0, 32);
    i = n_bits-1;
    tmp_bytes[31 - (i / 8)] |= (1 << (i % 8));
    secp256k1_scalar_set_b32(&ss, tmp_bytes, &overflow);
    secp256k1_scalar_inverse(&sv2, &ss);
    secp256k1_scalar_mul(&r[i], &sv1, &sv2);

    /* s[n - 1] =  -s * inverse_mod(2^(n-1)) */
    crypto_core_ed25519_scalar_negate(ev1, sum_s);

    memset(tmp_bytes, 0, 32);
    tmp_bytes[31 - (i / 8)] = 0;
    tmp_bytes[(i / 8)] |= (1 << (i % 8));
    crypto_core_ed25519_scalar_invert(ev2, tmp_bytes);
    crypto_core_ed25519_scalar_mul(s[i], ev1, ev2);

    secp256k1_sha256_initialize(&hash_state);
    secp256k1_sha256_write(hash_ctx, &hash_state, proof_out, 33);
    secp256k1_sha256_write(hash_ctx, &hash_state, proof_out + 33, 32);

    /* Create the commitment points */
    for (i = 0; i < n_bits; ++i) {
        int xi = key[31 - (i / 8)] & (1 << (i % 8));
        ps = xi ? &secp256k1_scalar_one : &secp256k1_scalar_zero;
        secp256k1_ecmult(&spj1, &gej_gen_s_a, ps, &secp256k1_scalar_zero);
        secp256k1_ecmult(&spj2, &gej_gen_s_b, &r[i], &secp256k1_scalar_zero);
        secp256k1_ge_set_gej(&s_pt, &spj2);
        secp256k1_gej_add_ge(&C_G[i], &spj1, &s_pt);

        if (!secp256k1_gej_serialize(ctx, tmp_bytes, &C_G[i])) {
            return 0;
        }
        secp256k1_sha256_write(hash_ctx, &hash_state, tmp_bytes, 33);

        pe = xi ? ed25519_sc_one : ed25519_sc_zero;
        ge25519_scalarmult(&ep1, pe, &gej_gen_e_a);
        ge25519_scalarmult(&ep2, s[i], &gej_gen_e_b);

        ge25519_p3_to_cached(&q_cached, &ep2);
        ge25519_add(&r_p1p1, &ep1, &q_cached);
        ge25519_p1p1_to_p3(&C_B[i], &r_p1p1);
        ge25519_p3_tobytes(tmp_bytes, &C_B[i]);
        secp256k1_sha256_write(hash_ctx, &hash_state, tmp_bytes, 32);
    }

    secp256k1_sha256_finalize(hash_ctx, &hash_state, preimage_hash);

    secp256k1_sha256_initialize( &hash_J);
    secp256k1_sha256_initialize(&hash_K);

    for (i = 0; i < n_bits; ++i) {
        unsigned char bJ[33];
        unsigned char bK[32];
        size_t xi = key[31 - (i / 8)] & (1 << (i % 8)) ? 1 : 0;
        if (!get_sc_secp256k1(&sc_j[i], hash_ctx, &rng) ||
            !get_sc_ed25519(sc_k[i], hash_ctx, &rng)) {
            return 0;
        }
        reverse32(key_r, sc_k[i]);
        memcpy(sc_k[i], key_r, 32);
        if (!secp256k1_raise_point_encode(ctx, bJ, &gej_gen_s_b, &sc_j[i])) {
            return 0;
        }
        if (0 != crypto_scalarmult_ed25519_noclamp(bK, sc_k[i], gen_e_b)) {
            return 0;
        }
        for (j = xi + 1; j < 2; ++j) {
            secp256k1_scalar ej;
            ed25519_scalar_t ek;
            dleag_hash(tmp_bytes, hash_ctx, preimage_hash, bJ, 33, bK, i, j);

            if (!hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes) ||
                !hash_sc_ed25519(ek, hash_ctx, tmp_bytes)) {
                return 0;
            }
            if (!get_sc_secp256k1(&sc_a[i * 2 + j], hash_ctx, &rng) ||
                !get_sc_ed25519(sc_b[i * 2 + j], hash_ctx, &rng)) {
                return 0;
            }

            /* j == 1 */
            /* J = HG * a[i * 2 + j] - (C_G[i] - G) * ej */
            secp256k1_ecmult(&spj1, &gej_gen_s_b, &sc_a[i * 2 + j], &secp256k1_scalar_zero);
            secp256k1_ge_set_gej(&s_pt, &gej_gen_s_a);
            secp256k1_ge_neg_inplace(&s_pt);
            secp256k1_gej_add_ge(&spj2, &C_G[i], &s_pt);
            secp256k1_ecmult(&spj2, &spj2, &ej, &secp256k1_scalar_zero);
            secp256k1_ge_set_gej(&s_pt, &spj2);
            secp256k1_ge_neg_inplace(&s_pt);
            secp256k1_gej_add_ge(&spj2, &spj1, &s_pt);
            if (!secp256k1_gej_serialize(ctx, bJ, &spj2)) {
                return 0;
            }

            /* K = HB * b[i * 2 + j]) - (C_B[i] - B) * ek */
            reverse32(key_r, sc_b[i * 2 + j]);
            ge25519_scalarmult(&ep1, key_r, &gej_gen_e_b);
            ge25519_p3_to_cached(&q_cached, &gej_gen_e_a);
            ge25519_sub(&r_p1p1, &C_B[i], &q_cached);
            ge25519_p1p1_to_p3(&ep2, &r_p1p1);
            reverse32(key_r, ek);
            ge25519_scalarmult(&ep2, key_r, &ep2);
            ge25519_p3_to_cached(&q_cached, &ep2);
            ge25519_sub(&r_p1p1, &ep1, &q_cached);
            ge25519_p1p1_to_p3(&ep2, &r_p1p1);
            ge25519_p3_tobytes(bK, &ep2);
        }
        secp256k1_sha256_write(hash_ctx, &hash_J, bJ, 33);
        secp256k1_sha256_write(hash_ctx, &hash_K, bK, 32);
    }
    secp256k1_sha256_finalize(hash_ctx, &hash_J, J_hash);
    secp256k1_sha256_finalize(hash_ctx, &hash_K, K_hash);


    /* Sign loop */
    for (i = 0; i < n_bits; ++i) {
        secp256k1_scalar ej;
        ed25519_scalar_t ek;
        unsigned char bJ[33];
        unsigned char bK[32];
        size_t xi = key[31 - (i / 8)] & (1 << (i % 8)) ? 1 : 0;
        dleag_hash(tmp_bytes, hash_ctx, preimage_hash, J_hash, 32, K_hash, i, 0);
        if (!hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes) ||
            !hash_sc_ed25519(ek, hash_ctx, tmp_bytes)) {
            return 0;
        }
        for (j = 0; j < xi; ++j) {
            if (!get_sc_secp256k1(&sc_a[i * 2 + j], hash_ctx, &rng) ||
                !get_sc_ed25519(sc_b[i * 2 + j], hash_ctx, &rng)) {
                return 0;
            }

            /* j == 0 */
            /* J = HG * a[i * 2 + j] - C_G[i] * ej */
            secp256k1_ecmult(&spj1, &gej_gen_s_b, &sc_a[i * 2 + j], &secp256k1_scalar_zero);
            secp256k1_ecmult(&spj2, &C_G[i], &ej, &secp256k1_scalar_zero);
            secp256k1_ge_set_gej(&s_pt, &spj2);
            secp256k1_ge_neg_inplace(&s_pt);
            secp256k1_gej_add_ge(&spj2, &spj1, &s_pt);
            if (!secp256k1_gej_serialize(ctx, bJ, &spj2)) {
                return 0;
            }

            /* K = HB * b[i * 2 + j] - C_B[i] * ek */
            reverse32(key_r, sc_b[i * 2 + j]);
            ge25519_scalarmult(&ep1, key_r, &gej_gen_e_b);
            reverse32(key_r, ek);
            ge25519_scalarmult(&ep2, key_r, &C_B[i]);
            ge25519_p3_to_cached(&q_cached, &ep2);
            ge25519_sub(&r_p1p1, &ep1, &q_cached);
            ge25519_p1p1_to_p3(&ep2, &r_p1p1);
            ge25519_p3_tobytes(bK, &ep2);

            dleag_hash(tmp_bytes, hash_ctx, preimage_hash, bJ, 33, bK, i, j + 1);
            if (!hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes) ||
                !hash_sc_ed25519(ek, hash_ctx, tmp_bytes)) {
                return 0;
            }
        }

        /* Close the loop
         * a[i * 2 + xi] = sc_j[i] + (ej * r[i])
         * b[i * 2 + xi] = sc_k[i] + (ek * s[i])
         */
        secp256k1_scalar_mul(&sv1, &ej, &r[i]);
        secp256k1_scalar_add(&sc_a[i * 2 + xi], &sc_j[i], &sv1);

        reverse32(key_r, ek);
        crypto_core_ed25519_scalar_mul(ev1, key_r, s[i]);
        crypto_core_ed25519_scalar_add(key_r, sc_k[i], ev1);
        reverse32(sc_b[i * 2 + xi], key_r);
    }

    *proof_len = 33 + 32 + 64 + 64;
    for (i = 0; i < n_bits; ++i) {
        if (!secp256k1_gej_serialize(ctx, proof_out + *proof_len, &C_G[i])) {
            return 0;
        }
        *proof_len += 33;
    }
    for (i = 0; i < n_bits; ++i) {
        ge25519_p3_tobytes(proof_out + *proof_len, &C_B[i]);
        *proof_len += 32;
    }
    memcpy(proof_out + *proof_len, J_hash, 32); *proof_len += 32;
    memcpy(proof_out + *proof_len, K_hash, 32); *proof_len += 32;
    for (i = 0; i < n_bits; ++i) {
        secp256k1_scalar_get_b32(proof_out + *proof_len, &sc_a[i * 2 + 0]);
        *proof_len += 32;
    }
    for (i = 0; i < n_bits; ++i) {
        secp256k1_scalar_get_b32(proof_out + *proof_len, &sc_a[i * 2 + 1]);
        *proof_len += 32;
    }
    for (i = 0; i < n_bits; ++i) {
        memcpy(proof_out + *proof_len, sc_b[i * 2 + 0], 32);
        *proof_len += 32;
    }
    for (i = 0; i < n_bits; ++i) {
        memcpy(proof_out + *proof_len, sc_b[i * 2 + 1], 32);
        *proof_len += 32;
    }

    return 1;
}

int secp256k1_dleag_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof,
    size_t proof_len,
    const secp256k1_generator *gen_s_a,
    const secp256k1_generator *gen_s_b,
    const unsigned char *gen_e_a,
    const unsigned char *gen_e_b) {
    size_t i, j;
    int overflow;
    secp256k1_gej gej_gen_s_a, gej_gen_s_b;
    ge25519_p3 gej_gen_e_a, gej_gen_e_b;
    secp256k1_ge s_pt;
    secp256k1_gej C_G[256];
    ge25519_p3 C_B[256];
    secp256k1_sha256 hash_state, hash_J, hash_K;
    secp256k1_gej sumG;
    ge25519_p3 sumB;
    unsigned char tmp_bytes[33];
    unsigned char preimage_hash[32], J_hash[32], K_hash[32];
    const unsigned char *pJ_hash, *pK_hash, *p_proof_a0, *p_proof_a1, *p_proof_b0, *p_proof_b1;
    secp256k1_gej spj1, spj2;
    ge25519_p3 ep1, ep2;
    ge25519_p1p1   r_p1p1;
    ge25519_cached q_cached;
    size_t n_bits = 252; /* TODO: Any bit length */
    size_t ofs = 0;
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(ctx);

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(gen_s_a != NULL);
    ARG_CHECK(gen_s_b != NULL);
    ARG_CHECK(gen_e_a != NULL);
    ARG_CHECK(gen_e_b != NULL);

    if (proof_len != secp256k1_dleag_size(n_bits)) {
        return 0;
    }

    secp256k1_generator_load(&s_pt, gen_s_a);
    secp256k1_gej_set_ge(&gej_gen_s_a, &s_pt);
    secp256k1_generator_load(&s_pt, gen_s_b);
    secp256k1_gej_set_ge(&gej_gen_s_b, &s_pt);

    if (ge25519_frombytes(&gej_gen_e_a, gen_e_a) != 0 ||
        ge25519_frombytes(&gej_gen_e_b, gen_e_b) != 0) {
        return 0;
    }

    /* Verify points are unblinded */
    {
    secp256k1_pubkey spk;
    secp256k1_ecdsa_signature sig;
    secp256k1_sha256_initialize(&hash_state);
    secp256k1_sha256_write(hash_ctx, &hash_state, (const unsigned char*) dleag_sig_message, strlen(dleag_sig_message));
    secp256k1_sha256_finalize(hash_ctx, &hash_state, preimage_hash);
    if (!secp256k1_ec_pubkey_parse(ctx, &spk, proof, 33) ||
        !secp256k1_ecdsa_signature_parse_compact(ctx, &sig, proof + 65) ||
        !secp256k1_ecdsa_verify_gen(ctx, &sig, preimage_hash, &spk, gen_s_a)) {
        return 0;
    }
    if (!ed25519_verify_gen(proof + 65 + 64, preimage_hash, 32, proof + 33, gen_e_a)) {
        return 0;
    }
    }

    /* Start the preimage hash */
    secp256k1_sha256_initialize(&hash_state);
    secp256k1_sha256_write(hash_ctx, &hash_state, proof, 33);
    secp256k1_sha256_write(hash_ctx, &hash_state, proof + 33, 32);

    /* Verify the weighted commitments sum to the points */
    secp256k1_gej_set_infinity(&sumG);
    ge25519_scalarmult_base(&sumB, ed25519_sc_zero);

    ofs = 65 + 64 + 64;
    for (i = 0; i < n_bits; ++i) {
        secp256k1_ge ge;
        secp256k1_gej sQ;
        ge25519_p3 eQ;
        secp256k1_scalar scs;
        ed25519_scalar_t sce;
        const unsigned char *sp = proof + ofs + i * 33;
        const unsigned char *ep = proof + ofs + n_bits * 33 + i * 32;
        if (!secp256k1_decode_check_point(&C_G[i], sp) ||
            !ed25519_decode_check_point(&C_B[i], ep)) {
            return 0;
        }
        secp256k1_sha256_write(hash_ctx, &hash_state, sp, 33);
        secp256k1_sha256_write(hash_ctx, &hash_state, ep, 32);

        /* sumG += C_G[i] * 2^i */
        /* sumB += C_B[i] * 2^i */
        if (i == 0) {
            secp256k1_ge_set_gej(&ge, &C_G[i]);
            ge25519_p3_to_cached(&q_cached, &C_B[i]);
        } else {
            secp256k1_scalar_clear(&scs);
            secp256k1_scalar_cadd_bit(&scs, i, 1);
            secp256k1_ecmult(&sQ, &C_G[i], &scs, &secp256k1_scalar_zero);
            secp256k1_ge_set_gej(&ge, &sQ);

            memset(sce, 0, 32);
            sce[(i / 8)] |= (1 << (i % 8));
            ge25519_scalarmult(&eQ, sce, &C_B[i]);
            ge25519_p3_to_cached(&q_cached, &eQ);
        }

        secp256k1_gej_add_ge(&sumG, &sumG, &ge);

        ge25519_add(&r_p1p1, &sumB, &q_cached);
        ge25519_p1p1_to_p3(&sumB, &r_p1p1);
    }

    secp256k1_gej_serialize(ctx, tmp_bytes, &sumG);
    if (0 != sodium_memcmp(proof, tmp_bytes, 33)) {
        return 0;
    }

    ge25519_p3_tobytes(tmp_bytes, &sumB);
    if (0 != sodium_memcmp(proof + 33, tmp_bytes, 32)) {
        return 0;
    }

    secp256k1_sha256_finalize(hash_ctx, &hash_state, preimage_hash);

    secp256k1_sha256_initialize(&hash_J);
    secp256k1_sha256_initialize(&hash_K);

    pJ_hash = proof + ofs + 65 * n_bits;
    pK_hash = proof + ofs + 65 * n_bits + 32;

    p_proof_a0 = proof + ofs + 65 * n_bits + 64;
    p_proof_a1 = p_proof_a0 + 32 * n_bits;
    p_proof_b0 = p_proof_a1 + 32 * n_bits;
    p_proof_b1 = p_proof_b0 + 32 * n_bits;

    for (i = 0; i < n_bits; ++i) {
        secp256k1_scalar ej, sc_a;
        ed25519_scalar_t ek, sc_b, tk;
        unsigned char bJ[33];
        unsigned char bK[32];
        dleag_hash(tmp_bytes, hash_ctx, preimage_hash, pJ_hash, 32, pK_hash, i, 0);
        if (!hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes) ||
            !hash_sc_ed25519(tk, hash_ctx, tmp_bytes)) {
            return 0;
        }
        reverse32(ek, tk);
        for (j = 0; j < 2; ++j) {
            secp256k1_scalar_set_b32(&sc_a, (j == 0 ? p_proof_a0 : p_proof_a1) + 32 * i, &overflow);
            if (overflow || secp256k1_scalar_is_zero(&sc_a)) {
                return 0;
            }

            if (!ed25519_decode_check_scalar(sc_b, (j == 0 ? p_proof_b0 : p_proof_b1) + 32 * i)) {
                return 0;
            }
            if (j == 0) {
                /* J = HG * a[i * 2 + j] - C_G[i] * ej */
                secp256k1_ecmult(&spj1, &gej_gen_s_b, &sc_a, &secp256k1_scalar_zero);
                secp256k1_ecmult(&spj2, &C_G[i], &ej, &secp256k1_scalar_zero);
                secp256k1_ge_set_gej(&s_pt, &spj2);
                secp256k1_ge_neg_inplace(&s_pt);
                secp256k1_gej_add_ge(&spj2, &spj1, &s_pt);
                if (!secp256k1_gej_serialize(ctx, bJ, &spj2)) {
                    return 0;
                }

                /* K = HB * b[i * 2 + j] - C_B[i] * ek */
                ge25519_scalarmult(&ep1, sc_b, &gej_gen_e_b);
                ge25519_scalarmult(&ep2, ek, &C_B[i]);
                ge25519_p3_to_cached(&q_cached, &ep2);
                ge25519_sub(&r_p1p1, &ep1, &q_cached);
                ge25519_p1p1_to_p3(&ep2, &r_p1p1);
                ge25519_p3_tobytes(bK, &ep2);

                /* Get new scalars for next iteration, j == 1 */
                dleag_hash(tmp_bytes, hash_ctx, preimage_hash, bJ, 33, bK, i, j + 1);
                if (!hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes) ||
                    !hash_sc_ed25519(tk, hash_ctx, tmp_bytes)) {
                    return 0;
                }
                reverse32(ek, tk);
            } else {
                /* J = HG * a[i * 2 + j] - (C_G[i] - G) * ej */
                secp256k1_ecmult(&spj1, &gej_gen_s_b, &sc_a, &secp256k1_scalar_zero);
                secp256k1_ge_set_gej(&s_pt, &gej_gen_s_a);
                secp256k1_ge_neg_inplace(&s_pt);
                secp256k1_gej_add_ge(&spj2, &C_G[i], &s_pt);
                secp256k1_ecmult(&spj2, &spj2, &ej, &secp256k1_scalar_zero);
                secp256k1_ge_set_gej(&s_pt, &spj2);
                secp256k1_ge_neg_inplace(&s_pt);
                secp256k1_gej_add_ge(&spj2, &spj1, &s_pt);
                if (!secp256k1_gej_serialize(ctx, bJ, &spj2)) {
                    return 0;
                }

                /* K = HB * b[i * 2 + j]) - (C_B[i] - B) * ek */
                ge25519_scalarmult(&ep1, sc_b, &gej_gen_e_b);
                ge25519_p3_to_cached(&q_cached, &gej_gen_e_a);
                ge25519_sub(&r_p1p1, &C_B[i], &q_cached);
                ge25519_p1p1_to_p3(&ep2, &r_p1p1);
                ge25519_scalarmult(&ep2, ek, &ep2);
                ge25519_p3_to_cached(&q_cached, &ep2);
                ge25519_sub(&r_p1p1, &ep1, &q_cached);
                ge25519_p1p1_to_p3(&ep2, &r_p1p1);
                ge25519_p3_tobytes(bK, &ep2);
            }
        }
        secp256k1_sha256_write(hash_ctx, &hash_J, bJ, 33);
        secp256k1_sha256_write(hash_ctx, &hash_K, bK, 32);
    }
    secp256k1_sha256_finalize(hash_ctx, &hash_J, J_hash);
    secp256k1_sha256_finalize(hash_ctx, &hash_K, K_hash);

    if (0 != sodium_memcmp(J_hash, pJ_hash, 32)) {
        return 0;
    }
    if (0 != sodium_memcmp(K_hash, pK_hash, 32)) {
        return 0;
    }

    return 1;
}

int secp256k1_dleag_verify_secp256k1_point(const secp256k1_context *ctx, const unsigned char *p) {
    secp256k1_gej P;
    VERIFY_CHECK(ctx != NULL);
    (void)ctx;
    return secp256k1_decode_check_point(&P, p);
}

int secp256k1_dleag_verify_ed25519_point(const secp256k1_context *ctx, const unsigned char *p) {
    ge25519_p3 P;
    VERIFY_CHECK(ctx != NULL);
    (void)ctx;
    return ed25519_decode_check_point(&P, p);
}

int secp256k1_ed25519_dleag_prove(
    const secp256k1_context *ctx,
    unsigned char *proof_out,
    size_t *proof_len,
    const unsigned char *key,
    size_t n_bits,
    const unsigned char *nonce) {
    return secp256k1_dleag_prove(ctx, proof_out, proof_len, key, n_bits, nonce,
                                 &secp256k1_generator_const_g, &secp256k1_generator_const_h,
                                 ed25519_gen, ed25519_gen2);
}

int secp256k1_ed25519_dleag_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof,
    size_t proof_len) {
    return secp256k1_dleag_verify(ctx, proof, proof_len,
                                  &secp256k1_generator_const_g, &secp256k1_generator_const_h,
                                  ed25519_gen, ed25519_gen2);
}

#endif
