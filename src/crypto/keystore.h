#ifndef DTL_CRYPTO_KEYSTORE_H
#define DTL_CRYPTO_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

/*
 * crypto/keystore -- an in-memory keystore holding the device key and a small
 * set of named key slots.
 *
 * The 32-byte device_key is a real secret, derived from the seed via the KDF at
 * init time. It is reachable only as a struct member; there is no decode path
 * that emits it, and neither the redaction pass nor the normal CLI reads it for
 * output. Slot material is exposed solely through dtl_keystore_slot, which
 * bounds-checks the id and refuses unused slots.
 */
#define DTL_KEYSTORE_SLOTS 8u
#define DTL_KEYSTORE_KEYLEN 32u

typedef struct dtl_keyslot {
    uint8_t data[32];
    uint8_t len;
    uint8_t used;
} dtl_keyslot;

typedef struct dtl_keystore {
    uint8_t     device_key[32];
    dtl_keyslot slots[DTL_KEYSTORE_SLOTS];
} dtl_keystore;

/*
 * dtl_keystore_init -- zero the whole keystore, then derive device_key from the
 * seed. After this every byte of the struct is defined and all slots are unused.
 */
void dtl_keystore_init(dtl_keystore *ks, const uint8_t *seed, size_t seed_len);

/*
 * dtl_keystore_slot -- return a pointer to slot_id's 32-byte data, or NULL if
 * slot_id is out of range or the slot is unused. Never reads out of bounds.
 */
const uint8_t *dtl_keystore_slot(const dtl_keystore *ks, uint8_t slot_id);

#endif /* DTL_CRYPTO_KEYSTORE_H */
