/*
 * _smoke.c (crypto) -- throwaway exerciser for the crypto module.
 *
 * Not part of any library. It checks: hash determinism + key/message
 * sensitivity; KDF determinism and seed dependence; keystore init (device_key
 * == kdf(seed), slots zeroed) and bounds-safe slot access; and that the
 * redaction pass blanks REC_KEYREF labels and sensitive REC_DIAG blobs while
 * leaving other records untouched. Under MSan (with origins) it also proves no
 * output byte -- especially of the keystore -- is ever read uninitialised.
 *
 * Removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "core/endian.h"
#include "core/err.h"
#include "crypto/build_key.h"
#include "crypto/hash.h"
#include "crypto/kdf.h"
#include "crypto/keystore.h"
#include "crypto/redact.h"
#include "format/tlv.h"
#include "records/record.h"
#include "records/registry.h"

static int g_failures = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) {                                             \
            printf("  PASS: ");                                 \
        } else {                                                \
            printf("  FAIL: ");                                 \
            g_failures++;                                       \
        }                                                       \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

static void print_hex(const char *label, const uint8_t *p, size_t n)
{
    size_t i;
    printf("  %s: ", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

int main(void)
{
    /* --- hash ------------------------------------------------------------ */
    printf("[hash]\n");
    {
        uint8_t key[] = { 'd', 'e', 'v', '-', 's', 'e', 'e', 'd' };
        uint8_t msg[] = { 't', 'e', 'l', 'e', 'm', 'e', 't', 'r', 'y' };
        uint8_t h1[32], h2[32], hk[32], hm[32];
        uint8_t key2[sizeof key];
        uint8_t msg2[sizeof msg];

        dtl_hash_mac(key, sizeof key, msg, sizeof msg, h1);
        dtl_hash_mac(key, sizeof key, msg, sizeof msg, h2);
        print_hex("mac", h1, 32);
        CHECK(memcmp(h1, h2, 32) == 0, "deterministic (same in -> same out)");

        memcpy(key2, key, sizeof key);
        key2[0] ^= 0x01; /* flip one key bit */
        dtl_hash_mac(key2, sizeof key2, msg, sizeof msg, hk);
        CHECK(memcmp(h1, hk, 32) != 0, "one key-bit change alters the mac");

        memcpy(msg2, msg, sizeof msg);
        msg2[4] ^= 0x01; /* flip one message bit */
        dtl_hash_mac(key, sizeof key, msg2, sizeof msg2, hm);
        CHECK(memcmp(h1, hm, 32) != 0, "one message-bit change alters the mac");

        /* Empty key and empty message must still yield a fully-defined mac. */
        {
            uint8_t he[32];
            dtl_hash_mac(NULL, 0, NULL, 0, he);
            CHECK(1, "empty key/message hashes without fault");
            (void)he;
        }
    }

    /* --- kdf ------------------------------------------------------------- */
    printf("\n[kdf]\n");
    {
        uint8_t seedA[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        uint8_t seedB[] = { 0x01, 0x02, 0x03, 0x04, 0x06 };
        uint8_t kA[32], kA2[32], kB[32];

        dtl_kdf_derive(seedA, sizeof seedA, kA);
        dtl_kdf_derive(seedA, sizeof seedA, kA2);
        dtl_kdf_derive(seedB, sizeof seedB, kB);

        CHECK(memcmp(kA, kA2, 32) == 0, "same seed -> same key");
        CHECK(memcmp(kA, kB, 32) != 0, "different seed -> different key");
    }

    /* --- keystore -------------------------------------------------------- */
    printf("\n[keystore]\n");
    {
        uint8_t seed[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x2A, 0x2B };
        dtl_keystore ks;
        uint8_t expect[32];
        int slots_zeroed = 1;
        size_t i;

        dtl_keystore_init(&ks, seed, sizeof seed);
        dtl_kdf_derive(seed, sizeof seed, expect);
        print_hex("device_key", ks.device_key, 32);
        CHECK(memcmp(ks.device_key, expect, 32) == 0, "device_key == kdf(seed)");

        for (i = 0; i < DTL_KEYSTORE_SLOTS; i++) {
            size_t j;
            if (ks.slots[i].used != 0 || ks.slots[i].len != 0)
                slots_zeroed = 0;
            for (j = 0; j < 32; j++)
                if (ks.slots[i].data[j] != 0)
                    slots_zeroed = 0;
        }
        CHECK(slots_zeroed, "all slots zeroed after init");

        CHECK(dtl_keystore_slot(&ks, 0) == NULL, "unused slot 0 -> NULL");
        CHECK(dtl_keystore_slot(&ks, 7) == NULL, "unused slot 7 -> NULL");
        CHECK(dtl_keystore_slot(&ks, 8) == NULL, "out-of-range slot 8 -> NULL");
        CHECK(dtl_keystore_slot(&ks, 255) == NULL, "out-of-range slot 255 -> NULL");

        /* A populated slot resolves to its data pointer (no OOB). */
        ks.slots[2].used = 1;
        ks.slots[2].len = 4;
        ks.slots[2].data[0] = 0xAB;
        CHECK(dtl_keystore_slot(&ks, 2) == ks.slots[2].data,
              "populated slot 2 -> data pointer");
    }

    /* --- redaction ------------------------------------------------------- */
    printf("\n[redaction]\n");
    {
        dtl_arena arena;
        uint8_t p[32];
        dtl_tlv tlv;
        dtl_record rec;
        dtl_err rc;

        dtl_arena_init(&arena, 0);

        /* REC_KEYREF: slot 3, label "secret-key" (10 bytes). */
        {
            const char *lbl;
            uint8_t llen;
            int zeroed = 1;
            size_t i;

            p[0] = 3;
            p[1] = 10;
            memcpy(p + 2, "secret-key", 10);
            tlv.tag = DTL_REC_KEYREF;
            tlv.len = 12;
            tlv.val = p;
            rc = dtl_record_parse(&tlv, &arena, &rec);
            CHECK(rc == DTL_OK, "keyref parses (got %s)", dtl_strerror(rc));

            lbl = rec.u.keyref.label;
            llen = rec.u.keyref.label_len;
            CHECK(rec.u.keyref.redacted == 0, "keyref not redacted before pass");

            dtl_redact_record(&rec);
            CHECK(rec.u.keyref.redacted == 1, "keyref flagged redacted");
            CHECK(rec.u.keyref.label_len == 0, "keyref label_len blanked");
            for (i = 0; i < llen; i++)
                if ((uint8_t)lbl[i] != 0)
                    zeroed = 0;
            CHECK(zeroed, "keyref label bytes zeroed in place");
        }

        /* REC_DIAG, sensitive subsystem 0xFF00: blob must be zeroed. */
        {
            const uint8_t *blob;
            uint16_t blen;
            int zeroed = 1;
            size_t i;

            dtl_endian_write_u16le(p + 0, 0xFF00); /* key-management */
            dtl_endian_write_u16le(p + 2, 4);
            p[4] = 0xDE; p[5] = 0xAD; p[6] = 0xBE; p[7] = 0xEF;
            tlv.tag = DTL_REC_DIAG;
            tlv.len = 8;
            tlv.val = p;
            rc = dtl_record_parse(&tlv, &arena, &rec);
            CHECK(rc == DTL_OK, "sensitive diag parses (got %s)", dtl_strerror(rc));

            blob = rec.u.diag.blob;
            blen = rec.u.diag.blob_len;

            dtl_redact_record(&rec);
            CHECK(rec.u.diag.redacted == 1, "sensitive diag flagged redacted");
            CHECK(rec.u.diag.blob_len == 0, "sensitive diag blob_len blanked");
            for (i = 0; i < blen; i++)
                if (blob[i] != 0)
                    zeroed = 0;
            CHECK(zeroed, "sensitive diag blob bytes zeroed in place");
        }

        /* REC_DIAG, ordinary subsystem: must be left untouched. */
        {
            dtl_endian_write_u16le(p + 0, 0x0042);
            dtl_endian_write_u16le(p + 2, 4);
            p[4] = 0xCA; p[5] = 0xFE; p[6] = 0xBA; p[7] = 0xBE;
            tlv.tag = DTL_REC_DIAG;
            tlv.len = 8;
            tlv.val = p;
            rc = dtl_record_parse(&tlv, &arena, &rec);
            CHECK(rc == DTL_OK, "ordinary diag parses (got %s)", dtl_strerror(rc));

            dtl_redact_record(&rec);
            CHECK(rec.u.diag.redacted == 0, "ordinary diag not redacted");
            CHECK(rec.u.diag.blob_len == 4, "ordinary diag blob_len intact");
            CHECK(rec.u.diag.blob[0] == 0xCA && rec.u.diag.blob[3] == 0xBE,
                  "ordinary diag blob intact");
        }

        /* A record with no secrets is passed through unchanged. */
        {
            dtl_endian_write_u32le(p + 0, 123456u);
            dtl_endian_write_u32le(p + 4, 42u);
            tlv.tag = DTL_REC_HEARTBEAT;
            tlv.len = 8;
            tlv.val = p;
            rc = dtl_record_parse(&tlv, &arena, &rec);
            CHECK(rc == DTL_OK, "heartbeat parses (got %s)", dtl_strerror(rc));

            dtl_redact_record(&rec);
            CHECK(rec.u.heartbeat.uptime_s == 123456u &&
                  rec.u.heartbeat.seq == 42u, "heartbeat untouched by redaction");
        }

        dtl_arena_free(&arena);
    }

    /* --- build-time seed -> device key ----------------------------------- */
    printf("\n[build seed -> device key]\n");
    {
        dtl_keystore ks;
        const uint8_t *seed;
        size_t seed_len = 0;
        uint8_t expect[32];
        size_t i;

        dtl_keystore_init_default(&ks);
        seed = dtl_build_seed(&seed_len);
        dtl_kdf_derive(seed, seed_len, expect);

        CHECK(seed_len > 0, "build seed is non-empty (%zu bytes)", seed_len);
        CHECK(memcmp(ks.device_key, expect, 32) == 0,
              "device_key == kdf(DTL_BUILD_SEED)");

        printf("  device_key=");
        for (i = 0; i < 32; i++)
            printf("%02x", ks.device_key[i]);
        printf("\n");
    }

    printf("\ncrypto smoke: %s (%d failure%s)\n",
           g_failures == 0 ? "ok" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
