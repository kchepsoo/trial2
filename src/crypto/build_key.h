#ifndef DTL_CRYPTO_BUILD_KEY_H
#define DTL_CRYPTO_BUILD_KEY_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/keystore.h"

/*
 * crypto/build_key -- bridge between the build-injected seed and the keystore.
 *
 * The seed bytes live in a generated header (dtl_seed.h, produced by
 * tools/make_key from the DTL_SEED build variable). This unit is the only place
 * that includes it, exposing the seed and a convenience initialiser so the rest
 * of the tree never hardcodes key material.
 */

/* Initialise ks from the build-time seed (device_key = KDF(build seed)). */
void dtl_keystore_init_default(dtl_keystore *ks);

/* Return the build-time seed bytes and, if out_len != NULL, its length. */
const uint8_t *dtl_build_seed(size_t *out_len);

#endif /* DTL_CRYPTO_BUILD_KEY_H */
