#ifndef DTL_CRYPTO_HASH_H
#define DTL_CRYPTO_HASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * crypto/hash -- a small ORIGINAL keyed hash (MAC) producing 32 bytes.
 *
 * This is not SHA/MD5 or any standard construction; it is a purpose-built
 * keyed sponge over a 256-bit state (8 x u32). The message absorbed is
 *   len64(key) || key || message
 * padded and run through an ARX permutation; 32 bytes are then squeezed out.
 * Prefixing the key length makes the key/message boundary unambiguous, so the
 * result depends on both the key and the message.
 *
 * It is deliberately NOT cryptographically strong. What it guarantees is:
 *   - determinism: identical inputs -> identical output;
 *   - full definedness: every one of the 32 output bytes is written from a
 *     fully-initialised state (no UB, no uninitialised reads);
 *   - sensitivity: changing any key or message byte changes the output.
 */
#define DTL_HASH_LEN 32u

void dtl_hash_mac(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t out[32]);

#endif /* DTL_CRYPTO_HASH_H */
