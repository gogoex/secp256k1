#ifndef SECP256K1_DLEAG_BLS_H
#define SECP256K1_DLEAG_BLS_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Cross-group DLEAG proof between secp256k1 and BLS12-381 (G1).
 *
 * Proves that a single 32-byte scalar `key` is the discrete log of a public key
 * on BOTH curves:
 *     X_secp = key * G_secp        (secp256k1 base generator)
 *     X_bls  = key * gen_a         (BLS12-381 G1 base point; a Navio blsct key)
 * without revealing `key`. This is the Navio counterpart of the existing
 * secp256k1<->ed25519 DLEAG (see secp256k1_dleag.h); the ed25519 track is
 * replaced by a BLS12-381 G1 track.
 *
 * Generators are fixed internally:
 *   secp:  G = secp256k1_generator_const_g , H = secp256k1_generator_const_h
 *   bls:   gen_a (G1 base point) , gen_b (NUMS) from the bls12_381 module.
 *
 * `key`   is 32-byte big-endian and must be < min(secp order, BLS Fr order),
 *         which holds for any value representable in `n_bits` bits (n_bits<=252).
 */

/* Create a proof.
 *
 * Returns: 1 on success, 0 on failure.
 * Out:  proof_out: buffer receiving the proof (cannot be NULL)
 * In/Out: proof_len: in = size of proof_out; out = bytes written
 * In:   key:    32-byte big-endian secret scalar (cannot be NULL)
 *       n_bits: number of bits to prove (<= 252)
 *       nonce:  32-byte randomness for the internal CSPRNG (cannot be NULL)
 */
SECP256K1_API int secp256k1_bls_dleag_prove(
    const secp256k1_context *ctx,
    unsigned char *proof_out,
    size_t *proof_len,
    const unsigned char *key,
    size_t n_bits,
    const unsigned char *nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(6);

/* Verify a proof.
 *
 * Returns: 1 if the proof is valid for n_bits, 0 otherwise.
 * In:   proof:     proof to verify (cannot be NULL)
 *       proof_len: length of proof; must equal the size for n_bits
 *       n_bits:    number of bits the proof must cover (1..252)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bls_dleag_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof,
    size_t proof_len,
    size_t n_bits
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_DLEAG_BLS_H */
