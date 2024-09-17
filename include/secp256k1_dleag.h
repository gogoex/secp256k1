#ifndef SECP256K1_DLEAG_H
#define SECP256K1_DLEAG_H

#include "secp256k1.h"
#include "secp256k1_ed25519.h"
#include "secp256k1_generator.h"
#include "secp256k1_recovery.h"

#ifdef __cplusplus
extern "C" {
#endif

SECP256K1_API size_t secp256k1_dleag_size(size_t n_bits);

SECP256K1_API int secp256k1_dleag_prove(
    const secp256k1_context *ctx,
    unsigned char *proof_out,
    size_t *proof_len,              /* Input length of proof_out buffer, output length of proof. */
    const unsigned char *key,       /* 32 bytes */
    size_t n_bits,
    const unsigned char *nonce,     /* 32 bytes */
    const secp256k1_generator *gen_s_a,
    const secp256k1_generator *gen_s_b,
    const unsigned char *gen_e_a,
    const unsigned char *gen_e_b
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleag_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof,
    size_t proof_len,
    const secp256k1_generator *gen_s_a,
    const secp256k1_generator *gen_s_b,
    const unsigned char *gen_e_a,
    const unsigned char *gen_e_b
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7);

/** Create a recoverable ECDSA signature.  Variable base point
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the secret key was invalid.
 *  Args:    ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_sign_recoverable_gen(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_recoverable_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata,
    const secp256k1_generator *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify an ECDSA signature.  Variable base point
 *
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 *  Args:    ctx:       a secp256k1 context object, initialized for verification.
 *  In:      sig:       the signature being verified (cannot be NULL)
 *           msg32:     the 32-byte message hash being verified (cannot be NULL)
 *           pubkey:    pointer to an initialized public key to verify with (cannot be NULL)
 *
 * To avoid accepting malleable signatures, only ECDSA signatures in lower-S
 * form are accepted.
 *
 * If you need to accept ECDSA signatures from sources that do not obey this
 * rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
 * validation, but be aware that doing so results in malleable signatures.
 *
 * For details, see the comments for that function.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_verify_gen(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey,
    const secp256k1_generator *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/**
 *  Returns: 1: signature created
 * seckey is BE
 * proof elements are returned in LE format
 * msg is hashed before signing
 */
SECP256K1_API int ed25519_sign_gen(
    unsigned char *sig,
    const unsigned char *msg,
    size_t mlen,
    const unsigned char *seckey,
    const unsigned char *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/**
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int ed25519_verify_gen(
    const unsigned char *sig,
    const unsigned char *msg,
    size_t mlen,
    const unsigned char *pubkey,
    const unsigned char *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleag_verify_secp256k1_point(
    const secp256k1_context *ctx,
    const unsigned char *p
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleag_verify_ed25519_point(
    const secp256k1_context *ctx,
    const unsigned char *p
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);


SECP256K1_API int secp256k1_ed25519_dleag_prove(
    const secp256k1_context *ctx,
    unsigned char *proof_out,
    size_t *proof_len,              /* Input length of proof_out buffer, output length of proof. */
    const unsigned char *key,       /* 32 bytes */
    size_t n_bits,
    const unsigned char *nonce     /* 32 bytes */
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ed25519_dleag_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof,
    size_t proof_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);


#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_DLEAG_H */
