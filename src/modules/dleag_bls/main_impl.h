#ifndef SECP256K1_DLEAG_BLS_MAIN
#define SECP256K1_DLEAG_BLS_MAIN

#include "../../../include/secp256k1_dleag_bls.h"
#include "../../../include/secp256k1_bls12_381.h"
#include "../../../include/secp256k1_generator.h"

static const char *dbls_sig_message = "dleag message";

static int dbls_ecdsa_sig_sign_gen(secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid, const secp256k1_gej *genj) {
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

static int dbls_ecdsa_sign_inner_gen(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, int* recid, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata, const secp256k1_gej *genj, const unsigned char *gen33) {
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
            ret = dbls_ecdsa_sig_sign_gen(r, s, &sec, &msg, &non, recid, genj);
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

static int dbls_ecdsa_sign_gen(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const unsigned char *seckey, const secp256k1_generator *gen) {
    secp256k1_scalar r, s;
    secp256k1_ge ge;
    secp256k1_gej genj;
    unsigned char gen33[33];
    int ret;

    if (!secp256k1_generator_serialize(ctx, gen33, gen)) {
        return 0;
    }
    secp256k1_generator_load(&ge, gen);
    secp256k1_gej_set_ge(&genj, &ge);

    ret = dbls_ecdsa_sign_inner_gen(ctx, &r, &s, NULL, msg32, seckey, NULL, NULL, &genj, gen33);
    secp256k1_scalar_get_b32(sig64, &r);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return ret;
}

SECP256K1_INLINE static void dbls_get_sc_secp256k1(secp256k1_scalar *sc, const secp256k1_hash_ctx *hash_ctx, secp256k1_rfc6979_hmac_sha256 *rng) {
    int overflow = 0;
    unsigned char tmp[32];
    do {
        secp256k1_rfc6979_hmac_sha256_generate(hash_ctx, rng, tmp, 32);
        secp256k1_scalar_set_b32(sc, tmp, &overflow);
    } while (overflow || secp256k1_scalar_is_zero(sc));
}

/* Draw a BLS scalar in [1, r) from the DRBG: clear the top bit (value < 2^255)
 * and retry until it is < r and non-zero. */
SECP256K1_INLINE static void dbls_bls_get_sc(secp256k1_bls_scalar *sc, const secp256k1_hash_ctx *hash_ctx, secp256k1_rfc6979_hmac_sha256 *rng) {
    unsigned char tmp[32];
    do {
        secp256k1_rfc6979_hmac_sha256_generate(hash_ctx, rng, tmp, 32);
        tmp[0] &= 0x7f;
    } while (!secp256k1_bls_scalar_set_b32(sc, tmp) || secp256k1_bls_scalar_is_zero(sc));
}

/* Map a 32-byte hash to a BLS scalar in [1, r) without bias: clear the top
 * bit (value < 2^255), and rehash until the value is < r and non-zero. */
static void dbls_bls_hash_to_scalar(const secp256k1_hash_ctx *hash_ctx, secp256k1_bls_scalar *out, const unsigned char *hash32) {
    secp256k1_sha256 hs;
    unsigned char buf[32];

    memcpy(buf, hash32, 32);
    while (1) {
        buf[0] &= 0x7f;
        if (secp256k1_bls_scalar_set_b32(out, buf) && !secp256k1_bls_scalar_is_zero(out)) {
            break;
        }
        secp256k1_sha256_initialize(&hs);
        secp256k1_sha256_write(hash_ctx, &hs, buf, 32);
        secp256k1_sha256_finalize(hash_ctx, &hs, buf);
    }
}

static const char dbls_bls_nonce_tag[] = "DLEAG/BLS/nonce";

/* Schnorr signature over a custom G1 generator: proves knowledge of x with
 * P = x * gen. Replaces ed25519_sign_gen from the ed25519 dleag. */
static int dbls_bls_sign_gen(
    const secp256k1_hash_ctx *hash_ctx,
    unsigned char *sig,             /* out: 80 bytes = R(48) || s(32) */
    const unsigned char *msg,
    size_t mlen,
    const unsigned char *seckey,    /* 32 bytes, big-endian */
    const unsigned char *gen) {     /* 48-byte compressed G1 point */
    secp256k1_bls_point genp, P, R;
    secp256k1_bls_scalar x, k, e, s;
    secp256k1_rfc6979_hmac_sha256 rng;
    secp256k1_sha256 hs;
    unsigned char P48[48], seed[32 + 48 + 32], buf[32];
    unsigned char acc = 0;
    size_t i;

    if (!secp256k1_bls_point_parse(&genp, gen)) {
        return 0;
    }
    for (i = 0; i < 30; ++i) acc |= seckey[i];  /* reject x < 2^16, like the original */
    if (!acc || !secp256k1_bls_scalar_set_b32(&x, seckey)) {
        return 0;
    }

    secp256k1_bls_point_mul(&P, &genp, &x);
    secp256k1_bls_point_serialize(P48, &P);

    /* k = HMAC-DRBG(x || gen || SHA256(tag || msg)), retried until 0 < k < r */
    secp256k1_sha256_initialize(&hs);
    secp256k1_sha256_write(hash_ctx, &hs, (const unsigned char *)dbls_bls_nonce_tag, sizeof(dbls_bls_nonce_tag) - 1);
    secp256k1_sha256_write(hash_ctx, &hs, msg, mlen);
    memcpy(seed, seckey, 32);
    memcpy(seed + 32, gen, 48);
    secp256k1_sha256_finalize(hash_ctx, &hs, seed + 80);
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng, seed, sizeof(seed));
    dbls_bls_get_sc(&k, hash_ctx, &rng);

    secp256k1_bls_point_mul(&R, &genp, &k);
    secp256k1_bls_point_serialize(sig, &R);

    /* e = SHA256(R || P || msg), mapped to [1, r) */
    secp256k1_sha256_initialize(&hs);
    secp256k1_sha256_write(hash_ctx, &hs, sig, 48);
    secp256k1_sha256_write(hash_ctx, &hs, P48, 48);
    secp256k1_sha256_write(hash_ctx, &hs, msg, mlen);
    secp256k1_sha256_finalize(hash_ctx, &hs, buf);
    dbls_bls_hash_to_scalar(hash_ctx, &e, buf);

    /* s = e * x + k */
    secp256k1_bls_scalar_mul(&s, &e, &x);
    secp256k1_bls_scalar_add(&s, &s, &k);
    secp256k1_bls_scalar_get_b32(sig + 48, &s);

    secp256k1_memclear_explicit(&x, sizeof(x));
    secp256k1_memclear_explicit(&k, sizeof(k));
    secp256k1_memclear_explicit(seed, sizeof(seed));
    secp256k1_memclear_explicit(buf, sizeof(buf));
    secp256k1_rfc6979_hmac_sha256_clear(&rng);
    return 1;
}

SECP256K1_INLINE static void dbls_ge_neg_inplace(secp256k1_ge *r) {
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

SECP256K1_INLINE static int dbls_raise_point_encode(const secp256k1_context *ctx, unsigned char *out, secp256k1_gej *P, const secp256k1_scalar *ss) {
    secp256k1_gej ptj;
    secp256k1_ecmult(&ptj, P, ss, &secp256k1_scalar_zero);
    return secp256k1_gej_serialize(ctx, out, &ptj);
}

/* Map a 32-byte hash to a secp256k1 scalar in [1, n): rehash until valid. */
SECP256K1_INLINE static int dbls_hash_sc_secp256k1(secp256k1_scalar *sc, const secp256k1_hash_ctx *hash_ctx, const unsigned char *bytes) {
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

/* e = SHA256(preimage || bJ || bK || BE32(i) || BE32(j)) */
SECP256K1_INLINE static void dbls_dleag_hash(
    unsigned char *out,
    const secp256k1_hash_ctx *hash_ctx,
    const unsigned char *preimage,
    const unsigned char *bJ, size_t len_j,
    const unsigned char *bK, size_t len_k,
    size_t i, size_t j) {
    unsigned char ring[4], epos[4];
    secp256k1_sha256 sha256_en;
    secp256k1_write_be32(ring, (uint32_t)i);
    secp256k1_write_be32(epos, (uint32_t)j);
    secp256k1_sha256_initialize(&sha256_en);
    secp256k1_sha256_write(hash_ctx, &sha256_en, preimage, 32);
    secp256k1_sha256_write(hash_ctx, &sha256_en, bJ, len_j);
    secp256k1_sha256_write(hash_ctx, &sha256_en, bK, len_k);
    secp256k1_sha256_write(hash_ctx, &sha256_en, ring, 4);
    secp256k1_sha256_write(hash_ctx, &sha256_en, epos, 4);
    secp256k1_sha256_finalize(hash_ctx, &sha256_en, out);
}

static size_t dbls_proof_size(size_t n_bits) {
    return 33 + 48 +      /* pubkeys: secp + G1 */
           64 + 80 +      /* sigs: ECDSA + Schnorr-G1 */
           64 +           /* J_hash + K_hash */
           209 * n_bits;  /* per bit: C_G(33) + C_B(48) + 4 scalars(128) */
}

int secp256k1_bls_dleag_prove(
    const secp256k1_context *ctx,
    unsigned char *proof_out,
    size_t *proof_len,
    const unsigned char *key,
    size_t n_bits,
    const unsigned char *nonce) {
    const secp256k1_generator *gen_s_a = &secp256k1_generator_const_g;
    const secp256k1_generator *gen_s_b = &secp256k1_generator_const_h;
    const unsigned char *gen_bls_a = secp256k1_bls_gen_a;
    const unsigned char *gen_bls_b = secp256k1_bls_gen_b;
    size_t i, j;
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char rngseed[32 + 33 + 48];
    unsigned char tmp_bytes[48];
    unsigned char preimage_hash[32], J_hash[32], K_hash[32];
    secp256k1_gej gej_gen_s_a, gej_gen_s_b;
    secp256k1_bls_point pt_gen_bls_a, pt_gen_bls_b;
    secp256k1_ge s_pt;
    secp256k1_scalar ss;
    secp256k1_scalar pow2;
    int overflow = 0;
    secp256k1_sha256 hash_state, hash_J, hash_K;
    secp256k1_scalar r[256];
    secp256k1_scalar sum_r;
    secp256k1_scalar sv1, sv2;
    secp256k1_bls_scalar s[256];
    secp256k1_bls_scalar sum_s;
    secp256k1_bls_scalar ev1, ev2;
    secp256k1_bls_scalar bls_one, bls_zero;
    secp256k1_gej C_G[256];
    secp256k1_gej spj1, spj2;
    const secp256k1_scalar *ps;
    const secp256k1_bls_scalar *pe;
    secp256k1_bls_point C_B[256];
    secp256k1_bls_point ep1, ep2;
    secp256k1_scalar sc_j[256];
    secp256k1_bls_scalar sc_k[256];
    secp256k1_scalar sc_a[256 * 2];
    secp256k1_bls_scalar sc_b[256 * 2];
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(ctx);

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof_out != NULL);
    ARG_CHECK(proof_len != NULL);
    ARG_CHECK(key != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(n_bits >= 1 && n_bits <= 252);

    if (*proof_len < dbls_proof_size(n_bits)) {
        return 0;
    }

    secp256k1_generator_load(&s_pt, gen_s_a);
    secp256k1_gej_set_ge(&gej_gen_s_a, &s_pt);
    secp256k1_generator_load(&s_pt, gen_s_b);
    secp256k1_gej_set_ge(&gej_gen_s_b, &s_pt);

    if (!secp256k1_bls_point_parse(&pt_gen_bls_a, gen_bls_a) ||
        !secp256k1_bls_point_parse(&pt_gen_bls_b, gen_bls_b)) {
        return 0;
    }

    /* s_pk = gen_s_a * key  -> proof_out[0..33) */
    /* Detect out-of-range keys: reject any bit set at position >= n_bits */
    for (i = n_bits; i < 256; ++i) {
        if (key[31 - (i / 8)] & (1 << (i % 8))) {
            return 0;
        }
    }
    secp256k1_scalar_set_b32(&ss, key, &overflow);
    if (overflow ||
        secp256k1_scalar_is_zero(&ss)) {
        secp256k1_scalar_clear(&ss);
        return 0;
    }
    if (!dbls_raise_point_encode(ctx, proof_out, &gej_gen_s_a, &ss)) {
        secp256k1_scalar_clear(&ss);
        return 0;
    }
    secp256k1_scalar_clear(&ss);

    /* bls_pk = gen_bls_a * key  -> proof_out[33..81) */
    if (!secp256k1_bls_scalar_set_b32(&ev1, key)) {
        return 0;
    }
    secp256k1_bls_point_mul(&ep1, &pt_gen_bls_a, &ev1);
    secp256k1_bls_point_serialize(proof_out + 33, &ep1);
    secp256k1_memclear_explicit(&ev1, sizeof(ev1));

    /* Include signatures to prove points are unblinded */
    {
    secp256k1_sha256_initialize(&hash_state);
    secp256k1_sha256_write(hash_ctx, &hash_state, (const unsigned char*) dbls_sig_message, strlen(dbls_sig_message));
    secp256k1_sha256_finalize(hash_ctx, &hash_state, preimage_hash);
    if (!dbls_ecdsa_sign_gen(ctx, proof_out + 81, preimage_hash, key, gen_s_a)) {
        return 0;
    }
    if (!dbls_bls_sign_gen(hash_ctx, proof_out + 81 + 64, preimage_hash, 32, key, gen_bls_a)) {
        return 0;
    }
    }

    /* Seed csprng */
    memcpy(rngseed, nonce, 32);
    memcpy(rngseed + 32, proof_out, 33 + 48);
    secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng, rngseed, sizeof(rngseed));

    /* Set the last r and s so they sum to 0 when weighted by bit position */
    secp256k1_scalar_set_int(&sum_r, 0);
    memset(tmp_bytes, 0, 32);
    if (!secp256k1_bls_scalar_set_b32(&bls_zero, tmp_bytes)) {
        return 0;
    }
    tmp_bytes[31] = 1;
    if (!secp256k1_bls_scalar_set_b32(&bls_one, tmp_bytes)) {
        return 0;
    }
    sum_s = bls_zero;
    for (i = 0; i < n_bits-1; ++i) {
        dbls_get_sc_secp256k1(&r[i], hash_ctx, &rng);
        dbls_bls_get_sc(&s[i], hash_ctx, &rng);

        secp256k1_scalar_cmov(&sv1, &r[i], 1);
        ev1 = s[i];
        if (i > 0) {
            secp256k1_scalar_clear(&pow2);
            secp256k1_scalar_cadd_bit(&pow2, i, 1);
            secp256k1_scalar_mul(&sv1, &sv1, &pow2);

            memset(tmp_bytes, 0, 32);
            tmp_bytes[31 - (i / 8)] |= (1 << (i % 8));
            if (!secp256k1_bls_scalar_set_b32(&ev2, tmp_bytes)) {
                return 0;
            }
            secp256k1_bls_scalar_mul(&ev1, &ev1, &ev2);
        }
        secp256k1_scalar_add(&sum_r, &sum_r, &sv1);
        secp256k1_bls_scalar_add(&sum_s, &sum_s, &ev1);
    }

    /* r[n - 1] =  -r * inverse_mod(2^(n-1)) */
    secp256k1_scalar_negate(&sv1, &sum_r);
    memset(tmp_bytes, 0, 32);
    i = n_bits-1;
    tmp_bytes[31 - (i / 8)] |= (1 << (i % 8));
    secp256k1_scalar_set_b32(&pow2, tmp_bytes, &overflow);
    secp256k1_scalar_inverse(&sv2, &pow2);
    secp256k1_scalar_mul(&r[i], &sv1, &sv2);

    /* s[n - 1] =  -s * inverse_mod(2^(n-1)) */
    secp256k1_bls_scalar_negate(&ev1, &sum_s);
    if (!secp256k1_bls_scalar_set_b32(&ev2, tmp_bytes)) {   /* tmp_bytes = 2^(n-1), BE */
        return 0;
    }
    secp256k1_bls_scalar_inverse(&ev2, &ev2);
    secp256k1_bls_scalar_mul(&s[i], &ev1, &ev2);

    secp256k1_sha256_initialize(&hash_state);
    secp256k1_sha256_write(hash_ctx, &hash_state, proof_out, 33);
    secp256k1_sha256_write(hash_ctx, &hash_state, proof_out + 33, 48);

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

        pe = xi ? &bls_one : &bls_zero;
        secp256k1_bls_point_mul(&ep1, &pt_gen_bls_a, pe);
        secp256k1_bls_point_mul(&ep2, &pt_gen_bls_b, &s[i]);
        secp256k1_bls_point_add(&C_B[i], &ep1, &ep2);
        secp256k1_bls_point_serialize(tmp_bytes, &C_B[i]);
        secp256k1_sha256_write(hash_ctx, &hash_state, tmp_bytes, 48);
    }

    secp256k1_sha256_finalize(hash_ctx, &hash_state, preimage_hash);

    secp256k1_sha256_initialize(&hash_J);
    secp256k1_sha256_initialize(&hash_K);

    for (i = 0; i < n_bits; ++i) {
        unsigned char bJ[33];
        unsigned char bK[48];
        size_t xi = key[31 - (i / 8)] & (1 << (i % 8)) ? 1 : 0;
        dbls_get_sc_secp256k1(&sc_j[i], hash_ctx, &rng);
        dbls_bls_get_sc(&sc_k[i], hash_ctx, &rng);
        if (!dbls_raise_point_encode(ctx, bJ, &gej_gen_s_b, &sc_j[i])) {
            return 0;
        }
        secp256k1_bls_point_mul(&ep1, &pt_gen_bls_b, &sc_k[i]);
        secp256k1_bls_point_serialize(bK, &ep1);
        for (j = xi + 1; j < 2; ++j) {
            secp256k1_scalar ej;
            secp256k1_bls_scalar ek;
            secp256k1_bls_point ep3;
            dbls_dleag_hash(tmp_bytes, hash_ctx, preimage_hash, bJ, 33, bK, 48, i, j);

            if (!dbls_hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes)) {
                return 0;
            }
            dbls_bls_hash_to_scalar(hash_ctx, &ek, tmp_bytes);
            dbls_get_sc_secp256k1(&sc_a[i * 2 + j], hash_ctx, &rng);
            dbls_bls_get_sc(&sc_b[i * 2 + j], hash_ctx, &rng);

            /* j == 1 */
            /* J = HG * a[i * 2 + j] - (C_G[i] - G) * ej */
            secp256k1_ecmult(&spj1, &gej_gen_s_b, &sc_a[i * 2 + j], &secp256k1_scalar_zero);
            secp256k1_ge_set_gej(&s_pt, &gej_gen_s_a);
            dbls_ge_neg_inplace(&s_pt);
            secp256k1_gej_add_ge(&spj2, &C_G[i], &s_pt);
            secp256k1_ecmult(&spj2, &spj2, &ej, &secp256k1_scalar_zero);
            secp256k1_ge_set_gej(&s_pt, &spj2);
            dbls_ge_neg_inplace(&s_pt);
            secp256k1_gej_add_ge(&spj2, &spj1, &s_pt);
            if (!secp256k1_gej_serialize(ctx, bJ, &spj2)) {
                return 0;
            }

            /* K = HB * b[i * 2 + j] - (C_B[i] - B) * ek */
            secp256k1_bls_point_mul(&ep1, &pt_gen_bls_b, &sc_b[i * 2 + j]);   /* ep1 = b*HB          */
            secp256k1_bls_point_sub(&ep2, &C_B[i], &pt_gen_bls_a);            /* ep2 = C_B - B       */
            secp256k1_bls_point_mul(&ep3, &ep2, &ek);                         /* ep3 = (C_B - B)*ek  */
            secp256k1_bls_point_sub(&ep2, &ep1, &ep3);                        /* ep2 = ep1 - ep3 = K */
            secp256k1_bls_point_serialize(bK, &ep2);
        }
        secp256k1_sha256_write(hash_ctx, &hash_J, bJ, 33);
        secp256k1_sha256_write(hash_ctx, &hash_K, bK, 48);
    }
    secp256k1_sha256_finalize(hash_ctx, &hash_J, J_hash);
    secp256k1_sha256_finalize(hash_ctx, &hash_K, K_hash);


    /* Sign loop */
    for (i = 0; i < n_bits; ++i) {
        secp256k1_scalar ej;
        secp256k1_bls_scalar ek;
        secp256k1_bls_point ep3;
        unsigned char bJ[33];
        unsigned char bK[48];
        size_t xi = key[31 - (i / 8)] & (1 << (i % 8)) ? 1 : 0;
        dbls_dleag_hash(tmp_bytes, hash_ctx, preimage_hash, J_hash, 32, K_hash, 32, i, 0);
        if (!dbls_hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes)) {
            return 0;
        }
        dbls_bls_hash_to_scalar(hash_ctx, &ek, tmp_bytes);
        for (j = 0; j < xi; ++j) {
            dbls_get_sc_secp256k1(&sc_a[i * 2 + j], hash_ctx, &rng);
            dbls_bls_get_sc(&sc_b[i * 2 + j], hash_ctx, &rng);

            /* j == 0 */
            /* J = HG * a[i * 2 + j] - C_G[i] * ej */
            secp256k1_ecmult(&spj1, &gej_gen_s_b, &sc_a[i * 2 + j], &secp256k1_scalar_zero);
            secp256k1_ecmult(&spj2, &C_G[i], &ej, &secp256k1_scalar_zero);
            secp256k1_ge_set_gej(&s_pt, &spj2);
            dbls_ge_neg_inplace(&s_pt);
            secp256k1_gej_add_ge(&spj2, &spj1, &s_pt);
            if (!secp256k1_gej_serialize(ctx, bJ, &spj2)) {
                return 0;
            }

            /* K = HB * b[i * 2 + j] - C_B[i] * ek */
            secp256k1_bls_point_mul(&ep1, &pt_gen_bls_b, &sc_b[i * 2 + j]);   /* ep1 = b*HB          */
            secp256k1_bls_point_mul(&ep2, &C_B[i], &ek);                      /* ep2 = C_B*ek        */
            secp256k1_bls_point_sub(&ep3, &ep1, &ep2);                        /* ep3 = ep1 - ep2 = K */
            secp256k1_bls_point_serialize(bK, &ep3);

            dbls_dleag_hash(tmp_bytes, hash_ctx, preimage_hash, bJ, 33, bK, 48, i, j + 1);
            if (!dbls_hash_sc_secp256k1(&ej, hash_ctx, tmp_bytes)) {
                return 0;
            }
            dbls_bls_hash_to_scalar(hash_ctx, &ek, tmp_bytes);
        }

        /* Close the loop
         * a[i * 2 + xi] = sc_j[i] + (ej * r[i])
         * b[i * 2 + xi] = sc_k[i] + (ek * s[i])
         */
        secp256k1_scalar_mul(&sv1, &ej, &r[i]);
        secp256k1_scalar_add(&sc_a[i * 2 + xi], &sc_j[i], &sv1);

        secp256k1_bls_scalar_mul(&ev1, &ek, &s[i]);
        secp256k1_bls_scalar_add(&sc_b[i * 2 + xi], &sc_k[i], &ev1);
    }

    *proof_len = 33 + 48 + 64 + 80;
    for (i = 0; i < n_bits; ++i) {
        if (!secp256k1_gej_serialize(ctx, proof_out + *proof_len, &C_G[i])) {
            return 0;
        }
        *proof_len += 33;
    }
    for (i = 0; i < n_bits; ++i) {
        secp256k1_bls_point_serialize(proof_out + *proof_len, &C_B[i]);
        *proof_len += 48;
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
        secp256k1_bls_scalar_get_b32(proof_out + *proof_len, &sc_b[i * 2 + 0]);
        *proof_len += 32;
    }
    for (i = 0; i < n_bits; ++i) {
        secp256k1_bls_scalar_get_b32(proof_out + *proof_len, &sc_b[i * 2 + 1]);
        *proof_len += 32;
    }
    VERIFY_CHECK(*proof_len == dbls_proof_size(n_bits));

    return 1;
}

#endif
