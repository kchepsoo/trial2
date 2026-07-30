/*
 * _smoke.c (format) -- throwaway exerciser for the format module.
 *
 * Not part of any library. It hand-builds DTL containers in a byte array and
 * checks that:
 *   - a valid container parses with the expected fields and its blob walks as a
 *     TLV stream;
 *   - deliberately malformed containers (bad header CRC, out-of-range section
 *     offset, truncated input) are rejected with the right error code and
 *     WITHOUT any out-of-bounds access -- so ASan/MSan stay silent.
 *
 * Removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "core/buf.h"
#include "core/endian.h"
#include "core/err.h"
#include "core/hexdump.h"
#include "format/container.h"
#include "format/crc.h"
#include "format/tlv.h"

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

/* Layout constants for the container we build below. */
#define HDR_LEN        12u
#define TABLE_ENTRY    16u
#define BLOB_OFF       (HDR_LEN + TABLE_ENTRY)   /* 28 */
#define BLOB_LEN       13u
#define TOTAL_LEN      (BLOB_OFF + BLOB_LEN)     /* 41 */

/*
 * Fill buf (>= TOTAL_LEN bytes) with a valid single-section container whose blob
 * is a 3-record TLV stream, and stamp a correct header_crc. Returns TOTAL_LEN.
 */
static size_t build_valid(uint8_t *buf)
{
    uint32_t crc;

    memset(buf, 0, TOTAL_LEN);

    /* header */
    buf[0] = 0x44; buf[1] = 0x54; buf[2] = 0x4C; buf[3] = 0x01; /* magic "DTL\1" */
    buf[4] = 0x01;                                              /* version */
    buf[5] = 0x00;                                              /* flags: none */
    dtl_endian_write_u16le(buf + 6, 1);                        /* section_count */
    /* buf[8..11] header_crc filled in below */

    /* section table entry 0 */
    dtl_endian_write_u16le(buf + 12, 0x0001);   /* type            */
    buf[14] = 0x00;                              /* codec_id: store */
    buf[15] = 0x00;                              /* reserved        */
    dtl_endian_write_u32le(buf + 16, BLOB_LEN);  /* raw_len         */
    dtl_endian_write_u32le(buf + 20, BLOB_LEN);  /* comp_len        */
    dtl_endian_write_u32le(buf + 24, 0);         /* offset          */

    /* blob region: TLV stream of three records */
    /* rec 0: tag 0x10, len 3, "abc" */
    buf[28] = 0x10; dtl_endian_write_u16le(buf + 29, 3);
    buf[31] = 'a'; buf[32] = 'b'; buf[33] = 'c';
    /* rec 1: tag 0x20, len 1, 0xff */
    buf[34] = 0x20; dtl_endian_write_u16le(buf + 35, 1);
    buf[37] = 0xff;
    /* rec 2: tag 0x30, len 0 */
    buf[38] = 0x30; dtl_endian_write_u16le(buf + 39, 0);

    /* header_crc over the first 8 header bytes */
    crc = dtl_crc32(buf, 8);
    dtl_endian_write_u32le(buf + 8, crc);

    return TOTAL_LEN;
}

int main(void)
{
    uint8_t buf[TOTAL_LEN];
    size_t len = build_valid(buf);

    printf("format smoke: built valid container, %zu bytes:\n", len);
    dtl_hexdump(stdout, buf, len);

    /* --- valid parse ------------------------------------------------------ */
    printf("\n[valid container]\n");
    {
        dtl_buf b;
        dtl_arena arena;
        dtl_container c;
        dtl_err rc;

        dtl_arena_init(&arena, 0);
        dtl_buf_init(&b, buf, len);
        rc = dtl_container_parse(&b, &arena, &c);

        CHECK(rc == DTL_OK, "parse returns DTL_OK (got \"%s\")", dtl_strerror(rc));
        if (rc == DTL_OK) {
            CHECK(c.version == 1, "version == 1 (got %u)", c.version);
            CHECK(c.flags == 0, "flags == 0 (got 0x%02x)", c.flags);
            CHECK(c.section_count == 1, "section_count == 1 (got %u)",
                  c.section_count);
            CHECK(c.hmac == NULL, "no hmac trailer");
            CHECK(c.sections != NULL, "section array allocated");

            if (c.sections != NULL) {
                dtl_section *s = &c.sections[0];
                CHECK(s->type == 0x0001, "section type == 1 (got %u)", s->type);
                CHECK(s->codec_id == 0, "codec_id == 0/store (got %u)",
                      s->codec_id);
                CHECK(s->raw_len == BLOB_LEN, "raw_len == %u (got %u)",
                      BLOB_LEN, s->raw_len);
                CHECK(s->comp_len == BLOB_LEN, "comp_len == %u (got %u)",
                      BLOB_LEN, s->comp_len);
                CHECK(s->offset == 0, "offset == 0 (got %u)", s->offset);
                CHECK(s->blob == buf + BLOB_OFF,
                      "blob points at blob region (+%u)", BLOB_OFF);

                /* Walk the store-codec blob as a TLV stream. */
                {
                    dtl_buf stream;
                    dtl_tlv rec;
                    size_t count = 0;
                    size_t counted = 0;

                    dtl_buf_init(&stream, s->blob, s->raw_len);

                    (void)dtl_tlv_count(&stream, &counted);
                    CHECK(counted == 3, "tlv_count == 3 (got %zu)", counted);

                    printf("  TLV walk:\n");
                    while (dtl_buf_remaining(&stream) != 0) {
                        dtl_err trc = dtl_tlv_next(&stream, &rec);
                        if (trc != DTL_OK) {
                            CHECK(0, "unexpected tlv error: %s",
                                  dtl_strerror(trc));
                            break;
                        }
                        printf("    rec %zu: tag=0x%02x len=%u\n",
                               count, rec.tag, rec.len);
                        count++;
                    }
                    CHECK(count == 3, "walked 3 records (got %zu)", count);
                }
            }
        }
        dtl_arena_free(&arena);
    }

    /* --- malformed: bad header CRC --------------------------------------- */
    printf("\n[malformed: bad header crc]\n");
    {
        uint8_t bad[TOTAL_LEN];
        dtl_buf b;
        dtl_arena arena;
        dtl_container c;
        dtl_err rc;

        memcpy(bad, buf, len);
        bad[8] ^= 0xff; /* corrupt stored header_crc */

        dtl_arena_init(&arena, 0);
        dtl_buf_init(&b, bad, len);
        rc = dtl_container_parse(&b, &arena, &c);
        CHECK(rc == DTL_ERR_BADHEADER,
              "rejected with DTL_ERR_BADHEADER (got \"%s\")", dtl_strerror(rc));
        dtl_arena_free(&arena);
    }

    /* --- malformed: section offset out of range -------------------------- */
    printf("\n[malformed: section offset out of range]\n");
    {
        uint8_t bad[TOTAL_LEN];
        dtl_buf b;
        dtl_arena arena;
        dtl_container c;
        dtl_err rc;

        memcpy(bad, buf, len);
        /* offset field lives at byte 24; header_crc does not cover the table,
         * so this stays a pure range violation, not a crc failure. */
        dtl_endian_write_u32le(bad + 24, 0x00010000u); /* 64 KiB, far past blob */

        dtl_arena_init(&arena, 0);
        dtl_buf_init(&b, bad, len);
        rc = dtl_container_parse(&b, &arena, &c);
        CHECK(rc == DTL_ERR_RANGE,
              "rejected with DTL_ERR_RANGE (got \"%s\")", dtl_strerror(rc));
        dtl_arena_free(&arena);
    }

    /* --- malformed: truncated input -------------------------------------- */
    printf("\n[malformed: truncated input]\n");
    {
        dtl_buf b;
        dtl_arena arena;
        dtl_container c;
        dtl_err rc;

        dtl_arena_init(&arena, 0);
        dtl_buf_init(&b, buf, HDR_LEN - 1); /* not even a full header */
        rc = dtl_container_parse(&b, &arena, &c);
        CHECK(rc == DTL_ERR_TRUNCATED,
              "rejected with DTL_ERR_TRUNCATED (got \"%s\")", dtl_strerror(rc));
        dtl_arena_free(&arena);
    }

    printf("\nformat smoke: %s (%d failure%s)\n",
           g_failures == 0 ? "ok" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
