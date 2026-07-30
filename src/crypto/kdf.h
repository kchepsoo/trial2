#ifndef DTL_CRYPTO_KDF_H
#define DTL_CRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>

/*
 * crypto/kdf -- derive the 32-byte device key from a build-time seed.
 *
 * The key is dtl_hash_mac keyed by the seed over a fixed domain-separation
 * label, so it is a deterministic pure function of the seed: the same seed
 * always yields the same key, and different seeds yield different keys. The
 * seed is injected at build time later; the KDF itself has no hidden state.
 */
void dtl_kdf_derive(const uint8_t *seed, size_t seed_len, uint8_t key_out[32]);

#endif /* DTL_CRYPTO_KDF_H */
