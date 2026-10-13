/**********************************************************************
 * Copyright (c) 2024                                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_BLS12_381_MAIN
#define SECP256K1_BLS12_381_MAIN

#include "../../../include/secp256k1_bls12_381.h"
#include "blst/bindings/blst.h"

/* The opaque public types are byte-compatible with blst's internal types:
 *   secp256k1_bls_scalar (4 x u64 = 256 bit)  <->  blst_fr   (Fr element)
 *   secp256k1_bls_point  (18 x u64 = 3x384)   <->  blst_p1   (G1 Jacobian)
 * Verified at compile time; we reinterpret across the boundary with casts. */
typedef char bls_scalar_size_check[(sizeof(secp256k1_bls_scalar) == sizeof(blst_fr)) ? 1 : -1];
typedef char bls_point_size_check[(sizeof(secp256k1_bls_point) == sizeof(blst_p1)) ? 1 : -1];

static SECP256K1_INLINE blst_fr *bls_fr(secp256k1_bls_scalar *s) { return (blst_fr *)s; }
static SECP256K1_INLINE const blst_fr *bls_fr_c(const secp256k1_bls_scalar *s) { return (const blst_fr *)s; }

/* Generators as 48-byte compressed G1 points (see header for derivation). */
const unsigned char secp256k1_bls_gen_a[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
    0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
    0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
};
const unsigned char secp256k1_bls_gen_b[48] = {
    0x99,0xea,0x5f,0x05,0x60,0x6a,0x78,0xe0,0x6d,0x00,0x18,0xd3,0x14,0x7e,0xb9,0xaa,
    0x56,0x9a,0x8d,0x4e,0x51,0xcb,0x57,0x0d,0x1b,0x4c,0x2a,0x76,0x23,0xe9,0x80,0x73,
    0xb9,0xa5,0x78,0x8c,0xe2,0xd8,0x58,0x92,0x5a,0x5b,0x66,0x72,0x4c,0xa9,0x53,0x3e
};

/* -------------------------------------------------------------------------- *
 *  Fr scalar arithmetic                                                      *
 * -------------------------------------------------------------------------- */

int secp256k1_bls_scalar_set_b32(secp256k1_bls_scalar *r, const unsigned char *be32) {
    blst_scalar sc;
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(be32 != NULL);
    blst_scalar_from_bendian(&sc, be32);
    if (!blst_scalar_fr_check(&sc)) {   /* reject value >= group order r */
        memset(r, 0, sizeof(*r));
        return 0;
    }
    blst_fr_from_scalar(bls_fr(r), &sc);
    return 1;
}

void secp256k1_bls_scalar_get_b32(unsigned char *be32, const secp256k1_bls_scalar *a) {
    blst_scalar sc;
    VERIFY_CHECK(be32 != NULL);
    VERIFY_CHECK(a != NULL);
    blst_scalar_from_fr(&sc, bls_fr_c(a));
    blst_bendian_from_scalar(be32, &sc);
}

int secp256k1_bls_scalar_is_zero(const secp256k1_bls_scalar *a) {
    unsigned char b[32];
    unsigned char acc = 0;
    size_t i;
    VERIFY_CHECK(a != NULL);
    secp256k1_bls_scalar_get_b32(b, a);
    for (i = 0; i < 32; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

void secp256k1_bls_scalar_add(secp256k1_bls_scalar *r, const secp256k1_bls_scalar *a, const secp256k1_bls_scalar *b) {
    VERIFY_CHECK(r != NULL); VERIFY_CHECK(a != NULL); VERIFY_CHECK(b != NULL);
    blst_fr_add(bls_fr(r), bls_fr_c(a), bls_fr_c(b));
}

void secp256k1_bls_scalar_mul(secp256k1_bls_scalar *r, const secp256k1_bls_scalar *a, const secp256k1_bls_scalar *b) {
    VERIFY_CHECK(r != NULL); VERIFY_CHECK(a != NULL); VERIFY_CHECK(b != NULL);
    blst_fr_mul(bls_fr(r), bls_fr_c(a), bls_fr_c(b));
}

void secp256k1_bls_scalar_negate(secp256k1_bls_scalar *r, const secp256k1_bls_scalar *a) {
    VERIFY_CHECK(r != NULL); VERIFY_CHECK(a != NULL);
    blst_fr_cneg(bls_fr(r), bls_fr_c(a), 1);   /* flag=1 -> negate */
}

void secp256k1_bls_scalar_inverse(secp256k1_bls_scalar *r, const secp256k1_bls_scalar *a) {
    VERIFY_CHECK(r != NULL); VERIFY_CHECK(a != NULL);
    blst_fr_inverse(bls_fr(r), bls_fr_c(a));   /* result undefined if a == 0 */
}

/* -------------------------------------------------------------------------- *
 *  G1 point arithmetic                                                       *
 * -------------------------------------------------------------------------- */

static SECP256K1_INLINE blst_p1 *bls_p1(secp256k1_bls_point *p) { return (blst_p1 *)p; }
static SECP256K1_INLINE const blst_p1 *bls_p1_c(const secp256k1_bls_point *p) { return (const blst_p1 *)p; }

int secp256k1_bls_point_parse(secp256k1_bls_point *r, const unsigned char *in48) {
    blst_p1_affine aff;
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(in48 != NULL);
    /* blst_p1_uncompress validates the encoding, that the point is on the curve
       and (in the vendored blst v0.3.17) prime-order subgroup membership.
       affine_in_g1 repeats the subgroup check so we do not depend on that blst
       behaviour. Neither rejects the identity, so we test is_inf ourselves below. */
    if (blst_p1_uncompress(&aff, in48) != BLST_SUCCESS ||
        !blst_p1_affine_in_g1(&aff)) {
        memset(r, 0, sizeof(*r));
        return 0;
    }
    blst_p1_from_affine(bls_p1(r), &aff);
    if (blst_p1_is_inf(bls_p1(r))) {
        memset(r, 0, sizeof(*r));
        return 0;
    }
    return 1;
}

void secp256k1_bls_point_serialize(unsigned char *out48, const secp256k1_bls_point *a) {
    VERIFY_CHECK(out48 != NULL);
    VERIFY_CHECK(a != NULL);
    blst_p1_compress(out48, bls_p1_c(a));
}

void secp256k1_bls_point_mul(secp256k1_bls_point *r, const secp256k1_bls_point *p, const secp256k1_bls_scalar *k) {
    blst_scalar sc;
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(p != NULL);
    VERIFY_CHECK(k != NULL);
    blst_scalar_from_fr(&sc, bls_fr_c(k));
    /* sc.b is little-endian; Fr < 2^255 so 255 bits suffice. */
    blst_p1_mult(bls_p1(r), bls_p1_c(p), sc.b, 255);
    memset(&sc, 0, sizeof(sc));   /* k may be secret */
}

void secp256k1_bls_point_add(secp256k1_bls_point *r, const secp256k1_bls_point *a, const secp256k1_bls_point *b) {
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(b != NULL);
    blst_p1_add_or_double(bls_p1(r), bls_p1_c(a), bls_p1_c(b));
}

void secp256k1_bls_point_sub(secp256k1_bls_point *r, const secp256k1_bls_point *a, const secp256k1_bls_point *b) {
    blst_p1 negb;
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(b != NULL);
    negb = *bls_p1_c(b);
    blst_p1_cneg(&negb, 1);   /* negate b */
    blst_p1_add_or_double(bls_p1(r), bls_p1_c(a), &negb);
}

void secp256k1_bls_point_set_infinity(secp256k1_bls_point *r) {
    VERIFY_CHECK(r != NULL);
    memset(r, 0, sizeof(*r));   /* all-zero limbs = point at infinity in blst */
}

#endif /* SECP256K1_BLS12_381_MAIN */
