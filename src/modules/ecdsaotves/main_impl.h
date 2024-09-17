/**********************************************************************
 * Copyright (c) 2020-2021 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECDSAOTVES_MAIN
#define SECP256K1_ECDSAOTVES_MAIN

#include "../../../include/secp256k1_ecdsaotves.h"

static const unsigned char base_point_encoded[33] = {
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
    0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
    0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
};

int ecdsaotves_enc_sign(
    const secp256k1_context *ctx,
    unsigned char *ct_out,
    const unsigned char *skS,
    const unsigned char *pkE,
    const unsigned char *msg32) {
    /* ct_out: R1, R2, s, K1, K2, r */
    secp256k1_gej PE, R1, R2, K1, K2;
    secp256k1_ge ge;
    secp256k1_scalar sec, non, non_dleq, msg, c, s, r2x, r;
    secp256k1_nonce_function noncefp = secp256k1_nonce_function_default;
    size_t count = 0;
    unsigned char tmp32[32];
    secp256k1_sha256 h;
    int rv = 1; /* Don't exit early, must reach memzero code */
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(ctx);

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(ct_out != NULL);
    ARG_CHECK(skS != NULL);
    ARG_CHECK(pkE != NULL);
    ARG_CHECK(msg32 != NULL);

    /* Fail if the encryption pubkey is invalid. */
    if (!secp256k1_eckey_pubkey_parse(&ge, pkE, 33) ||
        secp256k1_ge_is_infinity(&ge)) {
        return 0;
    }
    secp256k1_gej_set_ge(&PE, &ge);

    /* Fail if the secret key is invalid. */
    if (!secp256k1_scalar_set_b32_seckey(&sec, skS)) {
        secp256k1_scalar_clear(&sec);
        return 0;
    }
    /* Get nonce. */
    for (count = 0; count < 1000; ++count) {
        if (!noncefp(tmp32, msg32, skS, NULL, NULL, count)) {
            rv = 0;
            break;
        }
        if (secp256k1_scalar_set_b32_seckey(&non, tmp32)) {
            break;
        }
    }
    if (count >= 1000) {
        rv = 0;
    }
    if (rv) {
        /* R1 = G * nonce */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &R1, &non);

        /* R2 = pkE * nonce */
        secp256k1_ecmult(&R2, &PE, &non, &secp256k1_scalar_zero);

        /* Prove DLEQ: R1, R2 */
        /* Get DLEQ nonce. */
        for (count = 0; count < 1000; ++count) {
            static const char *algo16 = "DLEQ""DLEQ""DLEQ""DLEQ";
            if (!noncefp(tmp32, msg32, skS, (unsigned char*)algo16, (unsigned char*)pkE, count)) {
                rv = 0;
                break;
            }
            if (secp256k1_scalar_set_b32_seckey(&non_dleq, tmp32)) {
                break;
            }
        }
        if (count >= 1000) {
            rv = 0;
        }
    }
    if (rv) {
        /* K1 = G * non_dleq */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &K1, &non_dleq);
        /* K2 = pkE * non_dleq */
        secp256k1_ecmult(&K2, &PE, &non_dleq, &secp256k1_scalar_zero);

        if (!secp256k1_gej_serialize(ctx, ct_out, &R1) ||
            !secp256k1_gej_serialize(ctx, ct_out + 33, &R2) ||
            !secp256k1_gej_serialize(ctx, ct_out + 98, &K1) ||
            !secp256k1_gej_serialize(ctx, ct_out + 131, &K2)) {
            rv = 0;
        }
    }

    if (rv) {
        secp256k1_sha256_initialize(&h);
        secp256k1_sha256_write(hash_ctx, &h, ct_out, 66);              /* R1, R2 */
        secp256k1_sha256_write(hash_ctx, &h, ct_out + 66 + 32, 66);    /* K1, K2 */
        secp256k1_sha256_finalize(hash_ctx, &h, tmp32);
        secp256k1_scalar_set_b32(&c, tmp32, NULL);

        /* r = (non_dleq - (c * non) % o) % o */
        secp256k1_scalar_mul(&r, &c, &non);
        secp256k1_scalar_negate(&r, &r);
        secp256k1_scalar_add(&r, &non_dleq, &r);
        secp256k1_scalar_get_b32(ct_out + 164, &r);
        /* end dleq */

        /* r2x = R2.x % o */
        secp256k1_ge_set_gej(&ge, &R2);
        secp256k1_fe_normalize(&ge.x);
        secp256k1_fe_get_b32(tmp32, &ge.x);
        secp256k1_scalar_set_b32(&r2x, tmp32, NULL);
        rv = !secp256k1_scalar_is_zero(&r2x);
    }
    if (rv) {
        /* s = (inverse_mod(non, o) * ((msg + ((r2x * skS) % o)) % o)) % o */
        secp256k1_scalar_set_b32(&msg, msg32, NULL);
        secp256k1_scalar_mul(&r, &r2x, &sec);
        secp256k1_scalar_add(&s, &msg, &r);
        secp256k1_scalar_inverse(&r, &non);
        secp256k1_scalar_mul(&s, &r, &s);
        secp256k1_scalar_get_b32(ct_out + 66, &s);
        rv = !secp256k1_scalar_is_zero(&s);
    }

    /* memzero */
    sodium_memzero(tmp32, 32);
    secp256k1_scalar_clear(&r);
    secp256k1_scalar_clear(&r2x);
    secp256k1_scalar_clear(&msg);
    secp256k1_scalar_clear(&non);
    secp256k1_scalar_clear(&non_dleq);
    secp256k1_scalar_clear(&sec);

    return rv;
}

int ecdsaotves_enc_verify(
    const secp256k1_context *ctx,
    const unsigned char *pkS,
    const unsigned char *pkE,
    const unsigned char *msg32,
    const unsigned char *ct) {
    secp256k1_gej PS, PE, R1, R2, C1, C2, T1, T2;
    secp256k1_ge ge;
    secp256k1_scalar s, c, r, r2x, msg;
    unsigned char tmp33[33];
    secp256k1_sha256 h;
    const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(ctx);

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(pkS != NULL);
    ARG_CHECK(pkE != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(ct != NULL);

    if (!secp256k1_decode_check_point(&PS, pkS) ||
        !secp256k1_decode_check_point(&PE, pkE)) {
        return 0;
    }
    if (secp256k1_memcmp_var(ct,      base_point_encoded, 33) == 0 ||
        secp256k1_memcmp_var(ct + 33, base_point_encoded, 33) == 0) {
        return 0;
    }
    if (!secp256k1_decode_check_point(&R1, ct) ||
        !secp256k1_decode_check_point(&R2, ct + 33)) {
        return 0;
    }
    if (!secp256k1_scalar_set_b32_seckey(&s, ct + 66)) {
        return 0;
    }

    /* Verify DLEQ: G, PE, R1, R2 */
    if (!secp256k1_scalar_set_b32_seckey(&r, ct + 164)) {
        return 0;
    }
    if (secp256k1_memcmp_var(ct + 98, base_point_encoded, 33) == 0 ||    /* K1 == B1 */
        secp256k1_memcmp_var(ct + 98, pkE, 33) == 0 ||                   /* K1 == B2 */
        secp256k1_memcmp_var(ct + 131, base_point_encoded, 33) == 0 ||   /* K2 == B1 */
        secp256k1_memcmp_var(ct + 131, pkE, 33) == 0) {                  /* K2 == B2 */
        return 0;
    }
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(hash_ctx, &h, ct, 66);         /* R1, R2 */
    secp256k1_sha256_write(hash_ctx, &h, ct + 98, 66);    /* K1, K2 */
    secp256k1_sha256_finalize(hash_ctx, &h, tmp33);
    secp256k1_scalar_set_b32(&c, tmp33, NULL);

    /* T1 = B1 * r */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &T1, &r);
    /* T2 = B2 * r */
    secp256k1_ecmult(&T2, &PE, &r, &secp256k1_scalar_zero);

    /* C1 = P1 * c */
    secp256k1_ecmult(&C1, &R1, &c, &secp256k1_scalar_zero);
    /* C2 = P2 * c */
    secp256k1_ecmult(&C2, &R2, &c, &secp256k1_scalar_zero);

    secp256k1_ge_set_gej(&ge, &T1);
    secp256k1_gej_add_ge(&T1, &C1, &ge);
    secp256k1_ge_set_gej(&ge, &T2);
    secp256k1_gej_add_ge(&T2, &C2, &ge);

    if (secp256k1_gej_is_infinity(&T1) ||
        secp256k1_gej_is_infinity(&T2)) {
        return 0;
    }
    /* dleq True if K1 == T1 + C1 and K2 == T2 + C2 else False */
    if (!secp256k1_gej_serialize(ctx, tmp33, &T1) ||
        0 != secp256k1_memcmp_var(tmp33, ct + 98, 33) ||
        !secp256k1_gej_serialize(ctx, tmp33, &T2) ||
        0 != secp256k1_memcmp_var(tmp33, ct + 131, 33)) {
        return 0;
    }
    /* r2x = R2.x % o */
    secp256k1_ge_set_gej(&ge, &R2);
    secp256k1_fe_normalize(&ge.x);
    secp256k1_fe_get_b32(tmp33, &ge.x);
    secp256k1_scalar_set_b32(&r2x, tmp33, NULL);
    if (secp256k1_scalar_is_zero(&r2x)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    if (secp256k1_scalar_is_zero(&msg)) {
        return 0;
    }

    /* T = G * msg + pkS * R2x */
    secp256k1_ecmult(&T1, &PS, &r2x, &msg);

    /* True if R1 == T * si else False */
    secp256k1_scalar_inverse(&s, &s);
    secp256k1_ecmult(&T2, &T1, &s, &secp256k1_scalar_zero);
    if (!secp256k1_gej_serialize(ctx, tmp33, &T2) ||
        0 != secp256k1_memcmp_var(tmp33, ct, 33)) {
        return 0;
    }

    return 1;
}

int ecdsaotves_dec_sig(
    const secp256k1_context *ctx,
    unsigned char *sig_out,
    size_t *sig_length,
    const unsigned char *skE,
    const unsigned char *ct) {
    secp256k1_gej R2;
    secp256k1_ge ge;
    secp256k1_scalar s, sxe, r2x, ssig;
    unsigned char tmp32[32];
    int high;

    VERIFY_CHECK(ctx != NULL);
    (void)ctx;
    ARG_CHECK(sig_out != NULL);
    ARG_CHECK(sig_length != NULL);
    ARG_CHECK(skE != NULL);
    ARG_CHECK(ct != NULL);

    if (!secp256k1_decode_check_point(&R2, ct + 33) ||
        !secp256k1_scalar_set_b32_seckey(&s, ct + 66) ||
        !secp256k1_scalar_set_b32_seckey(&sxe, skE)) {
        return 0;
    }

    /* R2 == G * (b * r), Removing b */
    secp256k1_scalar_inverse(&sxe, &sxe);
    secp256k1_scalar_mul(&ssig, &s, &sxe);

    /* Low s */
    high = secp256k1_scalar_is_high(&ssig);
    secp256k1_scalar_cond_negate(&ssig, high);

    /* r2x = R2.x % o */
    secp256k1_ge_set_gej(&ge, &R2);
    secp256k1_fe_normalize(&ge.x);
    secp256k1_fe_get_b32(tmp32, &ge.x);
    secp256k1_scalar_set_b32(&r2x, tmp32, NULL);

    secp256k1_scalar_clear(&sxe);

    return secp256k1_ecdsa_sig_serialize(sig_out, sig_length, &r2x, &ssig);
}

int ecdsaotves_rec_enc_key(
    const secp256k1_context *ctx,
    unsigned char *key_out,
    const unsigned char *pkE,
    const unsigned char *ct,
    const unsigned char *dersig,
    size_t sig_length) {
    secp256k1_gej T;
    secp256k1_scalar sct, sigr, sigs, y;
    unsigned char tmp33[33];
    int rv = 1, found = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(key_out != NULL);
    ARG_CHECK(pkE != NULL);
    ARG_CHECK(ct != NULL);
    ARG_CHECK(dersig != NULL);

    if (!secp256k1_scalar_set_b32_seckey(&sct, ct + 66)) {
        return 0;
    }
    if (!secp256k1_ecdsa_sig_parse(&sigr, &sigs, dersig, sig_length)){
        return 0;
    }

    /* y = (inv(s) * sct) % o */
    secp256k1_scalar_inverse(&sigs, &sigs);
    secp256k1_scalar_mul(&y, &sigs, &sct);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &T, &y);

    if (!secp256k1_gej_serialize(ctx, tmp33, &T)) {
        rv = 0;
    }
    if (rv && 0 == sodium_memcmp(tmp33, pkE, 33)) {
        secp256k1_scalar_get_b32(key_out, &y);
        found = 1;
    }
    if (rv && !found) {
        secp256k1_scalar_negate(&y, &y);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &T, &y);
        if (!secp256k1_gej_serialize(ctx, tmp33, &T)) {
            rv = 0;
        }
        if (rv && 0 == sodium_memcmp(tmp33, pkE, 33)) {
            secp256k1_scalar_get_b32(key_out, &y);
            found = 1;
        }
    }

    sodium_memzero(tmp33, 33);
    secp256k1_scalar_clear(&y);
    secp256k1_scalar_clear(&sigs);
    secp256k1_scalar_clear(&sct);

    return rv & found;
}

#endif
