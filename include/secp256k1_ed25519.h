#ifndef SECP256K1_ED25519_H
#define SECP256K1_ED25519_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

SECP256K1_API const unsigned char ed25519_gen[32];
SECP256K1_API const unsigned char ed25519_gen2[32];
SECP256K1_API const unsigned char ed25519_sc_group_order_be[32];
SECP256K1_API const unsigned char ed25519_sc_zero[32];
SECP256K1_API const unsigned char ed25519_sc_one[32];


SECP256K1_API int ed25519_hash_to_curve_repeat(unsigned char r[32], const unsigned char in[32]);
SECP256K1_API int ed25519_hash_to_curve_elligator(unsigned char r[32], const unsigned char in[32]);
SECP256K1_API void reverse32(unsigned char *out, const unsigned char *in);
SECP256K1_API int ed25519_less_than_l_be(const unsigned char *in);

#if !defined(__clang__) && !defined(__GNUC__)
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif

/* From libsodium
 * crypto_core_ed25519.h
 */

#define SODIUM_EXPORT SECP256K1_API


#define crypto_core_ed25519_BYTES 32
SODIUM_EXPORT
size_t crypto_core_ed25519_bytes(void);

#define crypto_core_ed25519_UNIFORMBYTES 32
SODIUM_EXPORT
size_t crypto_core_ed25519_uniformbytes(void);

#define crypto_core_ed25519_HASHBYTES 64
SODIUM_EXPORT
size_t crypto_core_ed25519_hashbytes(void);

#define crypto_core_ed25519_SCALARBYTES 32
SODIUM_EXPORT
size_t crypto_core_ed25519_scalarbytes(void);

#define crypto_core_ed25519_NONREDUCEDSCALARBYTES 64
SODIUM_EXPORT
size_t crypto_core_ed25519_nonreducedscalarbytes(void);

SODIUM_EXPORT
int crypto_core_ed25519_is_valid_point(const unsigned char *p)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_core_ed25519_add(unsigned char *r,
                            const unsigned char *p, const unsigned char *q)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_core_ed25519_sub(unsigned char *r,
                            const unsigned char *p, const unsigned char *q)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_core_ed25519_from_uniform(unsigned char *p, const unsigned char *r)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_core_ed25519_from_hash(unsigned char *p, const unsigned char *h)
            __attribute__ ((nonnull)) __attribute__ ((deprecated));

/*
SODIUM_EXPORT
void crypto_core_ed25519_random(unsigned char *p)
            __attribute__ ((nonnull));

SODIUM_EXPORT
void crypto_core_ed25519_scalar_random(unsigned char *r)
            __attribute__ ((nonnull));
*/

SODIUM_EXPORT
int crypto_core_ed25519_scalar_invert(unsigned char *recip, const unsigned char *s)
            __attribute__ ((nonnull));

SODIUM_EXPORT
void crypto_core_ed25519_scalar_negate(unsigned char *neg, const unsigned char *s)
            __attribute__ ((nonnull));

SODIUM_EXPORT
void crypto_core_ed25519_scalar_complement(unsigned char *comp, const unsigned char *s)
            __attribute__ ((nonnull));

SODIUM_EXPORT
void crypto_core_ed25519_scalar_add(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
            __attribute__ ((nonnull));

SODIUM_EXPORT
void crypto_core_ed25519_scalar_sub(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
            __attribute__ ((nonnull));

SODIUM_EXPORT
void crypto_core_ed25519_scalar_mul(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
            __attribute__ ((nonnull));

/*
 * The interval `s` is sampled from should be at least 317 bits to ensure almost
 * uniformity of `r` over `L`.
 */
SODIUM_EXPORT
void crypto_core_ed25519_scalar_reduce(unsigned char *r, const unsigned char *s)
            __attribute__ ((nonnull));


/* From libsodium
 * crypto_scalarmult_ed25519.h
 */

#define crypto_scalarmult_ed25519_BYTES 32U
SODIUM_EXPORT
size_t crypto_scalarmult_ed25519_bytes(void);

#define crypto_scalarmult_ed25519_SCALARBYTES 32U
SODIUM_EXPORT
size_t crypto_scalarmult_ed25519_scalarbytes(void);

/*
 * NOTE: Do not use the result of this function directly for key exchange.
 *
 * Hash the result with the public keys in order to compute a shared
 * secret key: H(q || client_pk || server_pk)
 *
 * Or unless this is not an option, use the crypto_kx() API instead.
 */
SODIUM_EXPORT
int crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                              const unsigned char *p)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_scalarmult_ed25519_noclamp(unsigned char *q, const unsigned char *n,
                                      const unsigned char *p)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_scalarmult_ed25519_base(unsigned char *q, const unsigned char *n)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_scalarmult_ed25519_base_noclamp(unsigned char *q, const unsigned char *n)
            __attribute__ ((nonnull));



#define crypto_scalarmult_ristretto255_BYTES 32U
SODIUM_EXPORT
size_t crypto_scalarmult_ristretto255_bytes(void);

#define crypto_scalarmult_ristretto255_SCALARBYTES 32U
SODIUM_EXPORT
size_t crypto_scalarmult_ristretto255_scalarbytes(void);

/*
 * NOTE: Do not use the result of this function directly for key exchange.
 *
 * Hash the result with the public keys in order to compute a shared
 * secret key: H(q || client_pk || server_pk)
 *
 * Or unless this is not an option, use the crypto_kx() API instead.
 */
SODIUM_EXPORT
int crypto_scalarmult_ristretto255(unsigned char *q, const unsigned char *n,
                                   const unsigned char *p)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_scalarmult_ristretto255_base(unsigned char *q,
                                        const unsigned char *n)
            __attribute__ ((nonnull));



/* From libsodium
 * crypto_hash_sha512.h
 */

typedef struct crypto_hash_sha512_state {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buf[128];
} crypto_hash_sha512_state;

SODIUM_EXPORT
size_t crypto_hash_sha512_statebytes(void);

#define crypto_hash_sha512_BYTES 64U
SODIUM_EXPORT
size_t crypto_hash_sha512_bytes(void);

SODIUM_EXPORT
int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen) __attribute__ ((nonnull(1)));

SODIUM_EXPORT
int crypto_hash_sha512_init(crypto_hash_sha512_state *state)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                              const unsigned char *in,
                              unsigned long long inlen)
            __attribute__ ((nonnull(1)));

SODIUM_EXPORT
int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                             unsigned char *out)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int sodium_memcmp(const void *const b1_, const void *const b2_, size_t len);

SODIUM_EXPORT
void sodium_memzero(void * const pnt, const size_t len);


#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ED25519_H */
