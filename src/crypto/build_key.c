#include "crypto/build_key.h"

/* Generated at build time by tools/make_key from the DTL_SEED variable. */
#include "dtl_seed.h"

void dtl_keystore_init_default(dtl_keystore *ks)
{
    dtl_keystore_init(ks, DTL_BUILD_SEED, DTL_BUILD_SEED_LEN);
}

const uint8_t *dtl_build_seed(size_t *out_len)
{
    if (out_len != NULL)
        *out_len = DTL_BUILD_SEED_LEN;
    return DTL_BUILD_SEED;
}
