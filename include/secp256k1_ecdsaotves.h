#ifndef SECP256K1_ECDSAOTVES_H
#define SECP256K1_ECDSAOTVES_H

#include "secp256k1.h"
#include "secp256k1_generator.h"

#ifdef __cplusplus
extern "C" {
#endif

/* skS    - secret signing key
 * pkE    - public encryption key
 * m      - message
 * ct_out - ciphertext 196 bytes
 */
SECP256K1_API int ecdsaotves_enc_sign(
    const secp256k1_context *ctx,
    unsigned char *ct_out,
    const unsigned char *skS,
    const unsigned char *pkE,
    const unsigned char *msg32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int ecdsaotves_enc_verify(
    const secp256k1_context *ctx,
    const unsigned char *pkS,
    const unsigned char *pkE,
    const unsigned char *msg32,
    const unsigned char *ct
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

SECP256K1_API int ecdsaotves_dec_sig(
    const secp256k1_context *ctx,
    unsigned char *sig_out,
    size_t *sig_length,
    const unsigned char *skE,
    const unsigned char *ct
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

SECP256K1_API int ecdsaotves_rec_enc_key(
    const secp256k1_context *ctx,
    unsigned char *key_out,
    const unsigned char *pkE,
    const unsigned char *ct,
    const unsigned char *dersig,
    size_t sig_length
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSAOTVES_H */
