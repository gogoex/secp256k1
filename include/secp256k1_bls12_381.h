#ifndef SECP256K1_BLS12_381_H
#define SECP256K1_BLS12_381_H

#include "secp256k1.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** BLS12-381 module: minimal G1 / Fr arithmetic for DLEAG proofs.
 *
 *  This module exposes only the operations the cross-group DLEAG proof needs
 *  from BLS12-381: prime-order (r) scalar arithmetic in Fr, and point
 *  arithmetic in the prime-order G1 subgroup. Pairings, G2 and Fp12 are never
 *  used. The DLEAG-specific pieces (the Schnorr proof of knowledge that a
 *  committed key is unblinded, and the proof itself) live in the dleag_bls
 *  module and are built from the primitives below.
 *
 *  Wire encodings:
 *    - scalars: 32-byte big-endian, canonical (strictly less than the group
 *               order r).
 *    - points:  48-byte compressed G1 (ZCash/IETF encoding, matching Navio
 *               blsct's mclBn_setETHserialization(1)).
 *
 *  The opaque blobs below hold the backend's internal (Montgomery / Jacobian)
 *  representation. Treat them as opaque: only cross the byte boundary through
 *  set_b32 / get_b32 / parse / serialize.
 */

/** Opaque Fr scalar (256-bit backing store). */
typedef struct { uint64_t v[4]; } secp256k1_bls_scalar;

/** Opaque G1 point, projective/Jacobian form (three 384-bit coordinates). */
typedef struct { uint64_t v[18]; } secp256k1_bls_point;

/** Generators, as 48-byte compressed G1 points (parse with secp256k1_bls_point_parse).
 *
 *  gen_a: the standard BLS12-381 G1 base point. A DLEAG-committed public key is
 *         x * gen_a, i.e. exactly a Navio blsct public key (priv * base point).
 *  gen_b: an independent NUMS point, derived deterministically by hash-to-curve:
 *             gen_b = hash_to_g1(msg = gen_a compressed bytes,
 *                                DST = "SECP256K1_BLS12381_DLEAG_NUMS_GEN_B_V1")
 *         Used only to blind the DLEAG per-bit commitments. Because it comes
 *         from a hash, nobody knows log_{gen_a}(gen_b) -- which is what makes the
 *         bit commitments binding. The derivation is reproducible: anyone can
 *         recompute it and confirm no trapdoor was planted.
 *
 *  Scalar constants (0, 1) and weights (2^i) are not exported: build them from
 *  big-endian bytes via secp256k1_bls_scalar_set_b32 (e.g. 0x00..01 for one).
 */
SECP256K1_API const unsigned char secp256k1_bls_gen_a[48];
SECP256K1_API const unsigned char secp256k1_bls_gen_b[48];

/* -------------------------------------------------------------------------- *
 *  Fr scalar arithmetic (mod r)                                              *
 * -------------------------------------------------------------------------- */

/** Parse a 32-byte big-endian scalar.
 *
 *  Returns: 1 if the value is canonical (0 <= value < r); 0 otherwise.
 *  On failure *r is left cleared to zero.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bls_scalar_set_b32(
    secp256k1_bls_scalar *r,
    const unsigned char *be32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serialize a scalar to 32-byte big-endian. */
SECP256K1_API void secp256k1_bls_scalar_get_b32(
    unsigned char *be32,
    const secp256k1_bls_scalar *a
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Returns 1 if the scalar is zero, 0 otherwise. */
SECP256K1_API int secp256k1_bls_scalar_is_zero(
    const secp256k1_bls_scalar *a
) SECP256K1_ARG_NONNULL(1);

/** r = a + b  (mod r) */
SECP256K1_API void secp256k1_bls_scalar_add(
    secp256k1_bls_scalar *r,
    const secp256k1_bls_scalar *a,
    const secp256k1_bls_scalar *b
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** r = a * b  (mod r) */
SECP256K1_API void secp256k1_bls_scalar_mul(
    secp256k1_bls_scalar *r,
    const secp256k1_bls_scalar *a,
    const secp256k1_bls_scalar *b
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** r = -a  (mod r) */
SECP256K1_API void secp256k1_bls_scalar_negate(
    secp256k1_bls_scalar *r,
    const secp256k1_bls_scalar *a
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** r = a^-1  (mod r). Result is undefined if a == 0. */
SECP256K1_API void secp256k1_bls_scalar_inverse(
    secp256k1_bls_scalar *r,
    const secp256k1_bls_scalar *a
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/* -------------------------------------------------------------------------- *
 *  G1 point arithmetic                                                       *
 * -------------------------------------------------------------------------- */

/** Parse a 48-byte compressed G1 point.
 *
 *  Returns: 1 on success. Success requires a canonical encoding, a point on the
 *           curve, membership in the prime-order subgroup, and that the point is
 *           not the identity. Returns 0 otherwise (*r left cleared).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_bls_point_parse(
    secp256k1_bls_point *r,
    const unsigned char *in48
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serialize a point to 48-byte compressed G1. */
SECP256K1_API void secp256k1_bls_point_serialize(
    unsigned char *out48,
    const secp256k1_bls_point *a
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** r = k * p */
SECP256K1_API void secp256k1_bls_point_mul(
    secp256k1_bls_point *r,
    const secp256k1_bls_point *p,
    const secp256k1_bls_scalar *k
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** r = a + b */
SECP256K1_API void secp256k1_bls_point_add(
    secp256k1_bls_point *r,
    const secp256k1_bls_point *a,
    const secp256k1_bls_point *b
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** r = a - b */
SECP256K1_API void secp256k1_bls_point_sub(
    secp256k1_bls_point *r,
    const secp256k1_bls_point *a,
    const secp256k1_bls_point *b
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** r = identity (point at infinity). */
SECP256K1_API void secp256k1_bls_point_set_infinity(
    secp256k1_bls_point *r
) SECP256K1_ARG_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_BLS12_381_H */
