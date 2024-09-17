#include "../../../../include/secp256k1_ed25519.h"
#include "hash_sha512_cp.h"

size_t
crypto_hash_sha512_bytes(void)
{
    return crypto_hash_sha512_BYTES;
}

size_t
crypto_hash_sha512_statebytes(void)
{
    return sizeof(crypto_hash_sha512_state);
}
