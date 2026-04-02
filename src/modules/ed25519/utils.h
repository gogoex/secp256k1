
#ifndef SECP256K1_MODULE_ED25519_UTIL
#define SECP256K1_MODULE_ED25519_UTIL

#include <stdint.h>

void
sodium_add(unsigned char *a, const unsigned char *b, const size_t len)
{
    size_t        i;
    uint_fast16_t c = 0U;

    for (i = 0U; i < len; i++) {
        c += (uint_fast16_t) a[i] + (uint_fast16_t) b[i];
        a[i] = (unsigned char) c;
        c >>= 8;
    }
}

void
sodium_sub(unsigned char *a, const unsigned char *b, const size_t len)
{
    uint_fast16_t c = 0U;
    size_t        i;

    for (i = 0U; i < len; i++) {
        c = (uint_fast16_t) a[i] - (uint_fast16_t) b[i] - c;
        a[i] = (unsigned char) c;
        c = (c >> 8) & 1U;
    }
}

int
sodium_is_zero(const unsigned char *n, const size_t nlen)
{
    size_t                 i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
}

void
sodium_memzero(void * const pnt, const size_t len)
{
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
}

int
sodium_memcmp(const void *const b1_, const void *const b2_, size_t len)
{
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
    size_t                 i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

/*
 * sodium_compare() returns -1 if b1_ < b2_, 1 if b1_ > b2_ and 0 if b1_ == b2_
 */
int
sodium_compare_be(const unsigned char *b1_, const unsigned char *b2_, size_t len)
{
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
    size_t                 i;
    volatile unsigned char gt = 0U;
    volatile unsigned char eq = 1U;
    uint16_t               x1, x2;

    for (i = 0; i < len; i++) {
        x1 = b1[i];
        x2 = b2[i];
        gt |= (((unsigned int) x2 - (unsigned int) x1) >> 8) & eq;
        eq &= (((unsigned int) (x2 ^ x1)) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
}

#endif
