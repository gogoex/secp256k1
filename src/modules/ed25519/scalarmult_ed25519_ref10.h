
#ifndef SECP256K1_MODULE_ED25519_SCALARMULT
#define SECP256K1_MODULE_ED25519_SCALARMULT

#include <string.h>

#include "../../../include/secp256k1_ed25519.h"
#include "ref10/ed25519_ref10.h"
#include "utils.h"

static int
_crypto_scalarmult_ed25519_is_inf(const unsigned char s[32])
{
    unsigned char c;
    unsigned int  i;

    c = s[0] ^ 0x01;
    for (i = 1; i < 31; i++) {
        c |= s[i];
    }
    c |= s[31] & 0x7f;

    return ((((unsigned int) c) - 1U) >> 8) & 1;
}

static void
_crypto_scalarmult_ed25519_clamp(unsigned char k[32])
{
    k[0] &= 248;
    k[31] |= 64;
}

static int
_crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                           const unsigned char *p, const int clamp)
{
    unsigned char *t = q;
    ge25519_p3     Q;
    ge25519_p3     P;
    unsigned int   i;

    if (ge25519_is_canonical(p) == 0 || ge25519_has_small_order(p) != 0 ||
        ge25519_frombytes(&P, p) != 0 || ge25519_is_on_main_subgroup(&P) == 0) {
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    if (clamp != 0) {
        _crypto_scalarmult_ed25519_clamp(t);
    }
    t[31] &= 127;

    ge25519_scalarmult(&Q, t, &P);
    ge25519_p3_tobytes(q, &Q);
    if (_crypto_scalarmult_ed25519_is_inf(q) != 0 || sodium_is_zero(n, 32)) {
        return -1;
    }
    return 0;
}

int
crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                          const unsigned char *p)
{
    return _crypto_scalarmult_ed25519(q, n, p, 1);
}

int
crypto_scalarmult_ed25519_noclamp(unsigned char *q, const unsigned char *n,
                                  const unsigned char *p)
{
    return _crypto_scalarmult_ed25519(q, n, p, 0);
}

static int
_crypto_scalarmult_ed25519_base(unsigned char *q,
                                const unsigned char *n, const int clamp)
{
    unsigned char *t = q;
    ge25519_p3     Q;
    unsigned int   i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    if (clamp != 0) {
        _crypto_scalarmult_ed25519_clamp(t);
    }
    t[31] &= 127;

    ge25519_scalarmult_base(&Q, t);
    ge25519_p3_tobytes(q, &Q);
    if (_crypto_scalarmult_ed25519_is_inf(q) != 0 || sodium_is_zero(n, 32)) {
        return -1;
    }
    return 0;
}

int
crypto_scalarmult_ed25519_base(unsigned char *q,
                               const unsigned char *n)
{
    return _crypto_scalarmult_ed25519_base(q, n, 1);
}

int
crypto_scalarmult_ed25519_base_noclamp(unsigned char *q,
                                       const unsigned char *n)
{
    return _crypto_scalarmult_ed25519_base(q, n, 0);
}

size_t
crypto_scalarmult_ed25519_bytes(void)
{
    return crypto_scalarmult_ed25519_BYTES;
}

size_t
crypto_scalarmult_ed25519_scalarbytes(void)
{
    return crypto_scalarmult_ed25519_SCALARBYTES;
}

/* Ristretto group */

static int
ristretto255_sqrt_ratio_m1(fe25519 x, const fe25519 u, const fe25519 v)
{
    fe25519 v3;
    fe25519 vxx;
    fe25519 m_root_check, p_root_check, f_root_check;
    fe25519 x_sqrtm1;
    int     has_m_root, has_p_root, has_f_root;

    fe25519_sq(v3, v);
    fe25519_mul(v3, v3, v); /* v3 = v^3 */
    fe25519_sq(x, v3);
    fe25519_mul(x, x, v);
    fe25519_mul(x, x, u); /* x = uv^7 */

    fe25519_pow22523(x, x); /* x = (uv^7)^((q-5)/8) */
    fe25519_mul(x, x, v3);
    fe25519_mul(x, x, u); /* x = uv^3(uv^7)^((q-5)/8) */

    fe25519_sq(vxx, x);
    fe25519_mul(vxx, vxx, v); /* vx^2 */
    fe25519_sub(m_root_check, vxx, u); /* vx^2-u */
    fe25519_add(p_root_check, vxx, u); /* vx^2+u */
    fe25519_mul(f_root_check, u, sqrtm1); /* u*sqrt(-1) */
    fe25519_add(f_root_check, vxx, f_root_check); /* vx^2+u*sqrt(-1) */
    has_m_root = fe25519_iszero(m_root_check);
    has_p_root = fe25519_iszero(p_root_check);
    has_f_root = fe25519_iszero(f_root_check);
    fe25519_mul(x_sqrtm1, x, sqrtm1); /* x*sqrt(-1) */

    fe25519_cmov(x, x_sqrtm1, has_p_root | has_f_root);
    fe25519_abs(x, x);

    return has_m_root | has_p_root;
}

static int
ristretto255_is_canonical(const unsigned char *s)
{
    unsigned char c;
    unsigned char d;
    unsigned char e;
    unsigned int  i;

    c = (s[31] & 0x7f) ^ 0x7f;
    for (i = 30; i > 0; i--) {
        c |= s[i] ^ 0xff;
    }
    c = (((unsigned int) c) - 1U) >> 8;
    d = (0xed - 1U - (unsigned int) s[0]) >> 8;
    e = s[31] >> 7;

    return 1 - (((c & d) | e | s[0]) & 1);
}

int
ristretto255_frombytes(ge25519_p3 *h, const unsigned char *s)
{
    fe25519 inv_sqrt;
    fe25519 one;
    fe25519 s_;
    fe25519 ss;
    fe25519 u1, u2;
    fe25519 u1u1, u2u2;
    fe25519 v;
    fe25519 v_u2u2;
    int     was_square;

    if (ristretto255_is_canonical(s) == 0) {
        return -1;
    }
    fe25519_frombytes(s_, s);
    fe25519_sq(ss, s_);                /* ss = s^2 */

    fe25519_1(u1);
    fe25519_sub(u1, u1, ss);           /* u1 = 1-ss */
    fe25519_sq(u1u1, u1);              /* u1u1 = u1^2 */

    fe25519_1(u2);
    fe25519_add(u2, u2, ss);           /* u2 = 1+ss */
    fe25519_sq(u2u2, u2);              /* u2u2 = u2^2 */

    fe25519_mul(v, d1, u1u1);          /* v = d*u1^2 */
    fe25519_neg(v, v);                 /* v = -d*u1^2 */
    fe25519_sub(v, v, u2u2);           /* v = -(d*u1^2)-u2^2 */

    fe25519_mul(v_u2u2, v, u2u2);      /* v_u2u2 = v*u2^2 */

    fe25519_1(one);
    was_square = ristretto255_sqrt_ratio_m1(inv_sqrt, one, v_u2u2);
    fe25519_mul(h->X, inv_sqrt, u2);
    fe25519_mul(h->Y, inv_sqrt, h->X);
    fe25519_mul(h->Y, h->Y, v);

    fe25519_mul(h->X, h->X, s_);
    fe25519_add(h->X, h->X, h->X);
    fe25519_abs(h->X, h->X);
    fe25519_mul(h->Y, u1, h->Y);
    fe25519_1(h->Z);
    fe25519_mul(h->T, h->X, h->Y);

    return - ((1 - was_square) |
              fe25519_isnegative(h->T) | fe25519_iszero(h->Y));
}

void
ristretto255_p3_tobytes(unsigned char *s, const ge25519_p3 *h)
{
    fe25519 den1, den2;
    fe25519 den_inv;
    fe25519 eden;
    fe25519 inv_sqrt;
    fe25519 ix, iy;
    fe25519 one;
    fe25519 s_;
    fe25519 t_z_inv;
    fe25519 u1, u2;
    fe25519 u1_u2u2;
    fe25519 x_, y_;
    fe25519 x_z_inv;
    fe25519 z_inv;
    fe25519 zmy;
    int     rotate;

    fe25519_add(u1, h->Z, h->Y);       /* u1 = Z+Y */
    fe25519_sub(zmy, h->Z, h->Y);      /* zmy = Z-Y */
    fe25519_mul(u1, u1, zmy);          /* u1 = (Z+Y)*(Z-Y) */
    fe25519_mul(u2, h->X, h->Y);       /* u2 = X*Y */

    fe25519_sq(u1_u2u2, u2);           /* u1_u2u2 = u2^2 */
    fe25519_mul(u1_u2u2, u1, u1_u2u2); /* u1_u2u2 = u1*u2^2 */

    fe25519_1(one);
    (void) ristretto255_sqrt_ratio_m1(inv_sqrt, one, u1_u2u2);
    fe25519_mul(den1, inv_sqrt, u1);   /* den1 = inv_sqrt*u1 */
    fe25519_mul(den2, inv_sqrt, u2);   /* den2 = inv_sqrt*u2 */
    fe25519_mul(z_inv, den1, den2);    /* z_inv = den1*den2 */
    fe25519_mul(z_inv, z_inv, h->T);   /* z_inv = den1*den2*T */

    fe25519_mul(ix, h->X, sqrtm1);     /* ix = X*sqrt(-1) */
    fe25519_mul(iy, h->Y, sqrtm1);     /* iy = Y*sqrt(-1) */
    fe25519_mul(eden, den1, invsqrtamd); /* eden = den1/sqrt(a-d) */

    fe25519_mul(t_z_inv, h->T, z_inv); /* t_z_inv = T*z_inv */
    rotate = fe25519_isnegative(t_z_inv);

    fe25519_copy(x_, h->X);
    fe25519_copy(y_, h->Y);
    fe25519_copy(den_inv, den2);

    fe25519_cmov(x_, iy, rotate);
    fe25519_cmov(y_, ix, rotate);
    fe25519_cmov(den_inv, eden, rotate);

    fe25519_mul(x_z_inv, x_, z_inv);
    fe25519_cneg(y_, y_, fe25519_isnegative(x_z_inv));

    fe25519_sub(s_, h->Z, y_);
    fe25519_mul(s_, den_inv, s_);
    fe25519_abs(s_, s_);
    fe25519_tobytes(s, s_);
}

static void
ristretto255_elligator(ge25519_p3 *p, const fe25519 t)
{
    fe25519 c;
    fe25519 n;
    fe25519 one;
    fe25519 r;
    fe25519 rpd;
    fe25519 s, s_prime;
    fe25519 ss;
    fe25519 u, v;
    fe25519 w0, w1, w2, w3;
    int     wasnt_square;

    fe25519_1(one);
    fe25519_sq(r, t);                  /* r = t^2 */
    fe25519_mul(r, sqrtm1, r);         /* r = sqrt(-1)*t^2 */
    fe25519_add(u, r, one);            /* u = r+1 */
    fe25519_mul(u, u, onemsqd);        /* u = (r+1)*(1-d^2) */
    fe25519_1(c);
    fe25519_neg(c, c);                 /* c = -1 */
    fe25519_add(rpd, r, d1);           /* rpd = r*d */
    fe25519_mul(v, r, d1);             /* v = r*d */
    fe25519_sub(v, c, v);              /* v = c-r*d */
    fe25519_mul(v, v, rpd);            /* v = (c-r*d)*(r+d) */

    wasnt_square = 1 - ristretto255_sqrt_ratio_m1(s, u, v);
    fe25519_mul(s_prime, s, t);
    fe25519_abs(s_prime, s_prime);
    fe25519_neg(s_prime, s_prime);     /* s_prime = -|s*t| */
    fe25519_cmov(s, s_prime, wasnt_square);
    fe25519_cmov(c, r, wasnt_square);

    fe25519_sub(n, r, one);            /* n = r-1 */
    fe25519_mul(n, n, c);              /* n = c*(r-1) */
    fe25519_mul(n, n, sqdmone);        /* n = c*(r-1)*(d-1)^2 */
    fe25519_sub(n, n, v);              /* n =  c*(r-1)*(d-1)^2-v */

    fe25519_add(w0, s, s);             /* w0 = 2s */
    fe25519_mul(w0, w0, v);            /* w0 = 2s*v */
    fe25519_mul(w1, n, sqrtadm1);      /* w1 = n*sqrt(ad-1) */
    fe25519_sq(ss, s);                 /* ss = s^2 */
    fe25519_sub(w2, one, ss);          /* w2 = 1-s^2 */
    fe25519_add(w3, one, ss);          /* w3 = 1+s^2 */

    fe25519_mul(p->X, w0, w3);
    fe25519_mul(p->Y, w2, w1);
    fe25519_mul(p->Z, w1, w3);
    fe25519_mul(p->T, w0, w2);
}

void
ristretto255_from_hash(unsigned char s[32], const unsigned char h[64])
{
    fe25519        r0, r1;
    ge25519_cached p1_cached;
    ge25519_p1p1   p_p1p1;
    ge25519_p3     p0, p1;
    ge25519_p3     p;

    fe25519_frombytes(r0, h);
    fe25519_frombytes(r1, h + 32);
    ristretto255_elligator(&p0, r0);
    ristretto255_elligator(&p1, r1);
    ge25519_p3_to_cached(&p1_cached, &p1);
    ge25519_add(&p_p1p1, &p0, &p1_cached);
    ge25519_p1p1_to_p3(&p, &p_p1p1);
    ristretto255_p3_tobytes(s, &p);
}

int
crypto_scalarmult_ristretto255(unsigned char *q, const unsigned char *n,
                               const unsigned char *p)
{
    unsigned char *t = q;
    ge25519_p3     Q;
    ge25519_p3     P;
    unsigned int   i;

    if (ristretto255_frombytes(&P, p) != 0) {
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;
    ge25519_scalarmult(&Q, t, &P);
    ristretto255_p3_tobytes(q, &Q);
    if (sodium_is_zero(q, 32)) {
        return -1;
    }
    return 0;
}

int
crypto_scalarmult_ristretto255_base(unsigned char *q,
                                    const unsigned char *n)
{
    unsigned char *t = q;
    ge25519_p3     Q;
    unsigned int   i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;
    ge25519_scalarmult_base(&Q, t);
    ristretto255_p3_tobytes(q, &Q);
    if (sodium_is_zero(q, 32)) {
        return -1;
    }
    return 0;
}

size_t
crypto_scalarmult_ristretto255_bytes(void)
{
    return crypto_scalarmult_ristretto255_BYTES;
}

size_t
crypto_scalarmult_ristretto255_scalarbytes(void)
{
    return crypto_scalarmult_ristretto255_SCALARBYTES;
}

#endif
