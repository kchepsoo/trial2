#include "crypto/keystore.h"

#include <string.h>

#include "crypto/kdf.h"

void dtl_keystore_init(dtl_keystore *ks, const uint8_t *seed, size_t seed_len)
{
    /* Zero everything first: device_key and every slot (data/len/used). This
     * leaves no byte of the struct undefined. */
    memset(ks, 0, sizeof *ks);
    dtl_kdf_derive(seed, seed_len, ks->device_key);
}

const uint8_t *dtl_keystore_slot(const dtl_keystore *ks, uint8_t slot_id)
{
    if (slot_id >= DTL_KEYSTORE_SLOTS)
        return NULL;
    if (!ks->slots[slot_id].used)
        return NULL;
    return ks->slots[slot_id].data;
}
