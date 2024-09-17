/**********************************************************************
 * Copyright (c) 2020 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ED25519_MAIN
#define SECP256K1_MODULE_ED25519_MAIN

#include "../../../include/secp256k1_ed25519.h"

const unsigned char ed25519_gen[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

const unsigned char ed25519_gen2[32] = { /* sha256(ed25519_gen), repeat until point is valid */
    0x13, 0xb6, 0x63, 0xe5, 0xe0, 0x6b, 0xf5, 0x30,
    0x1c, 0x77, 0x47, 0x3b, 0xb2, 0xfc, 0x5b, 0xeb,
    0x51, 0xe4, 0x04, 0x6e, 0x9b, 0x7e, 0xfe, 0xf2,
    0xf6, 0xd1, 0xa3, 0x24, 0xcb, 0x8b, 0x10, 0x94
};

const unsigned char ed25519_sc_group_order_be[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
    0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
};

const unsigned char ed25519_sc_zero[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const unsigned char ed25519_sc_one[32] = { /* little endian */
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int ed25519_hash_to_curve_repeat(unsigned char r[32], const unsigned char in[32]) {
    size_t i;
    secp256k1_sha256 hasher;
    ge25519_p3 p3;
    ge25519_p2 p2;
    secp256k1_hash_ctx hash_ctx;
    secp256k1_hash_ctx_init(&hash_ctx);

    memcpy(r, in, 32);
    for (i = 0; i < 1000; ++i) {
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hash_ctx, &hasher, r, 32);
        secp256k1_sha256_finalize(&hash_ctx, &hasher, r);

        if (ge25519_frombytes(&p3, r) != 0) {
            continue;
        }

        if (ge25519_is_on_curve(&p3) &&
            ge25519_is_on_main_subgroup(&p3)) {
            ge25519_p3_to_p2(&p2, &p3);
            ge25519_tobytes(r, &p2);
            return 1;
        }
    }
    return 0;
}

int ed25519_hash_to_curve_elligator(unsigned char r[32], const unsigned char in[32]) {
    unsigned char t[32];
    secp256k1_sha256 hasher;
    secp256k1_hash_ctx hash_ctx;
    secp256k1_hash_ctx_init(&hash_ctx);
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hash_ctx, &hasher, in, 32);
    secp256k1_sha256_finalize(&hash_ctx, &hasher, t);
    crypto_core_ed25519_from_uniform(r, t);
    return 1;
}

void reverse32(unsigned char *out, const unsigned char *in) {
    size_t i;
    for (i = 0; i < 32; ++i) {
        out[i] = in[31 - i];
    }
}

int ed25519_less_than_l_be(const unsigned char *in) {
    int yes = 0;
    int no = 0;
    int i;
    for (i = 31; i >= 0; i--) {
        yes = in[i] < ed25519_sc_group_order_be[i];
        no &= yes;
    }
    return yes;
}

#endif
