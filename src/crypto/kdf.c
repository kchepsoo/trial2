#include "crypto/kdf.h"

#include "crypto/hash.h"

/* Domain-separation label; kept out of the seed so unrelated MACs never collide. */
static const char DTL_KDF_LABEL[] = "DTL-DEVICE-KEY-v1";

void dtl_kdf_derive(const uint8_t *seed, size_t seed_len, uint8_t key_out[32])
{
    /* key = MAC(key = seed, msg = label). Deterministic in the seed. */
    dtl_hash_mac(seed, seed_len,
                 (const uint8_t *)DTL_KDF_LABEL, sizeof DTL_KDF_LABEL - 1u,
                 key_out);
}
