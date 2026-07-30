/*
 * _smoke.c (codec) -- throwaway exerciser for codec/ pass 1 (store, rle, varint).
 *
 * Not part of any library. For each codec, fetched through the registry, it:
 *   - round-trips several buffers (encode then decode == original);
 *   - feeds malformed/truncated input to decode and checks the right error;
 *   - feeds an undersized out_cap and checks DTL_ERR_RANGE.
 * All of this must run with no sanitizer report across plain/asan/msan --
 * correct rejection, never a caught overflow.
 *
 * Removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/endian.h"
#include "core/err.h"
#include "codec/registry.h"

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

/* encode(orig) then decode, asserting the result equals the original. */
static void roundtrip(const dtl_codec *c, const uint8_t *orig, size_t n,
                      const char *label)
{
    uint8_t enc[2048];
    uint8_t dec[2048];
    size_t enc_len = 0;
    size_t dec_len = 0;
    dtl_err rc;

    rc = c->encode(orig, n, enc, sizeof enc, &enc_len);
    if (rc != DTL_OK) {
        CHECK(0, "%s: %s encode failed: %s", c->name, label, dtl_strerror(rc));
        return;
    }
    rc = c->decode(enc, enc_len, dec, sizeof dec, &dec_len);
    if (rc != DTL_OK) {
        CHECK(0, "%s: %s decode failed: %s", c->name, label, dtl_strerror(rc));
        return;
    }
    CHECK(dec_len == n && (n == 0 || memcmp(dec, orig, n) == 0),
          "%s: %s round-trip (%zu -> %zu -> %zu)",
          c->name, label, n, enc_len, dec_len);
}

/* Build a little-endian u32 buffer for the varint tests. */
static size_t put_u32s(uint8_t *buf, const uint32_t *vals, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        dtl_endian_write_u32le(buf + i * 4, vals[i]);
    return count * 4;
}

int main(void)
{
    const dtl_codec *store = dtl_codec_get(DTL_CODEC_STORE);
    const dtl_codec *rle = dtl_codec_get(DTL_CODEC_RLE);
    const dtl_codec *varint = dtl_codec_get(DTL_CODEC_VARINT);
    const dtl_codec *lz77 = dtl_codec_get(DTL_CODEC_LZ77);
    const dtl_codec *dict = dtl_codec_get(DTL_CODEC_DICT);
    const dtl_codec *delta = dtl_codec_get(DTL_CODEC_DELTA);
    const dtl_codec *base32 = dtl_codec_get(DTL_CODEC_BASE32);

    /* --- registry -------------------------------------------------------- */
    printf("[registry]\n");
    CHECK(store && strcmp(store->name, "store") == 0, "id 0 -> store");
    CHECK(rle && strcmp(rle->name, "rle") == 0, "id 1 -> rle");
    CHECK(varint && strcmp(varint->name, "varint") == 0, "id 2 -> varint");
    CHECK(lz77 && strcmp(lz77->name, "lz77") == 0, "id 3 -> lz77");
    CHECK(dict && strcmp(dict->name, "dict") == 0, "id 4 -> dict");
    CHECK(delta && strcmp(delta->name, "delta") == 0, "id 5 -> delta");
    CHECK(base32 && strcmp(base32->name, "base32") == 0, "id 6 -> base32");
    CHECK(dtl_codec_get(7) == NULL, "id 7 unknown -> NULL");
    CHECK(dtl_codec_get(200) == NULL, "id 200 unknown -> NULL");

    if (!store || !rle || !varint || !lz77 || !dict || !delta || !base32) {
        printf("codec smoke: FAILED (registry incomplete)\n");
        return 1;
    }

    /* --- store ----------------------------------------------------------- */
    printf("\n[store id 0]\n");
    {
        static const uint8_t msg[] = "Hello, DTL!";
        static const uint8_t pat[16] = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
        };
        roundtrip(store, msg, sizeof msg - 1, "text");
        roundtrip(store, pat, sizeof pat, "pattern");
        roundtrip(store, pat, 0, "empty");

        /* out_cap smaller than the data must be refused, not truncated. */
        {
            uint8_t out[4];
            size_t ol = 0;
            dtl_err rc = store->decode((const uint8_t *)"hello", 5,
                                       out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode cap-too-small -> RANGE (got %s)",
                  dtl_strerror(rc));
        }
    }

    /* --- rle ------------------------------------------------------------- */
    printf("\n[rle id 1]\n");
    {
        static const uint8_t mixed[] = "aaaaabbbccccccccd";
        uint8_t longrun[300];
        uint8_t nonrep[16];
        size_t i;

        memset(longrun, 'Z', sizeof longrun);      /* >255 -> multiple runs */
        for (i = 0; i < sizeof nonrep; i++)
            nonrep[i] = (uint8_t)(i * 17u);         /* no adjacent repeats   */

        roundtrip(rle, mixed, sizeof mixed - 1, "mixed runs");
        roundtrip(rle, longrun, sizeof longrun, "300-byte run");
        roundtrip(rle, nonrep, sizeof nonrep, "non-repeating");
        roundtrip(rle, mixed, 0, "empty");

        {
            uint8_t out[64];
            size_t ol = 0;
            dtl_err rc;

            /* Odd-length input: a count with no value byte. */
            rc = rle->decode((const uint8_t[]){ 0x03 }, 1, out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_TRUNCATED, "decode odd-length -> TRUNCATED (got %s)",
                  dtl_strerror(rc));

            /* Zero run count is malformed. */
            rc = rle->decode((const uint8_t[]){ 0x00, 0x41 }, 2,
                             out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_BADRECORD, "decode zero-count -> BADRECORD (got %s)",
                  dtl_strerror(rc));

            /* {5,'A'} expands to 5 bytes but out_cap is 3. */
            rc = rle->decode((const uint8_t[]){ 0x05, 0x41 }, 2, out, 3, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode cap-too-small -> RANGE (got %s)",
                  dtl_strerror(rc));
        }
    }

    /* --- varint ---------------------------------------------------------- */
    printf("\n[varint id 2]\n");
    {
        static const uint32_t vals[] = {
            0u, 1u, 127u, 128u, 300u, 16384u, 0xFFFFFFFFu
        };
        uint8_t raw[sizeof vals];
        size_t raw_len = put_u32s(raw, vals, sizeof vals / sizeof vals[0]);

        roundtrip(varint, raw, raw_len, "u32 sequence");
        roundtrip(varint, raw, 0, "empty");

        {
            uint8_t out[64];
            size_t ol = 0;
            dtl_err rc;

            /* Continuation bit set with no following byte. */
            rc = varint->decode((const uint8_t[]){ 0x80 }, 1, out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_TRUNCATED, "decode dangling-continuation -> TRUNCATED (got %s)",
                  dtl_strerror(rc));

            /* Six continuation groups overflow a u32. */
            rc = varint->decode((const uint8_t[]){ 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 },
                                6, out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode 6-group overflow -> RANGE (got %s)",
                  dtl_strerror(rc));

            /* Fifth group carries more than the 4 bits a u32 has left. */
            rc = varint->decode((const uint8_t[]){ 0x80, 0x80, 0x80, 0x80, 0x10 },
                                5, out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode fifth-group overflow -> RANGE (got %s)",
                  dtl_strerror(rc));

            /* {0x01} decodes to a 4-byte u32 but out_cap is 3. */
            rc = varint->decode((const uint8_t[]){ 0x01 }, 1, out, 3, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode cap-too-small -> RANGE (got %s)",
                  dtl_strerror(rc));

            /* Encode rejects a trailing partial u32. */
            rc = varint->encode((const uint8_t[]){ 0x01, 0x02, 0x03 }, 3,
                                out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_TRUNCATED, "encode partial-u32 -> TRUNCATED (got %s)",
                  dtl_strerror(rc));
        }
    }

    /* --- lz77 ------------------------------------------------------------ */
    printf("\n[lz77 id 3]\n");
    {
        static const uint8_t text[] = "the cat sat on the mat, the cat sat flat";
        uint8_t allsame[512];
        uint8_t pat3[300];
        size_t i;

        memset(allsame, 'A', sizeof allsame); /* offset-1 overlapping matches */
        for (i = 0; i < sizeof pat3; i++)
            pat3[i] = (uint8_t)("ABC"[i % 3]); /* offset-3 overlapping matches */

        roundtrip(lz77, text, sizeof text - 1, "repetitive text");
        roundtrip(lz77, allsame, sizeof allsame, "512-byte single run");
        roundtrip(lz77, pat3, sizeof pat3, "ABC-repeat (overlap)");
        roundtrip(lz77, text, 1, "one byte");
        roundtrip(lz77, text, 0, "empty");

        {
            uint8_t out[64];
            size_t ol = 0;
            dtl_err rc;

            /* Match at the very start: offset 1 > 0 bytes written. */
            rc = lz77->decode((const uint8_t[]){ 0x01, 0x00, 0x00 }, 3,
                              out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_BADRECORD, "decode match-at-start -> BADRECORD (got %s)",
                  dtl_strerror(rc));

            /* One literal then a match whose offset (5) exceeds bytes written (1). */
            rc = lz77->decode((const uint8_t[]){ 0x02, 0x41, 0x04, 0x00 }, 4,
                              out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_BADRECORD, "decode offset-too-large -> BADRECORD (got %s)",
                  dtl_strerror(rc));

            /* A single literal token but out_cap is 0. */
            rc = lz77->decode((const uint8_t[]){ 0x00, 0x41 }, 2, out, 0, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode literal-past-cap -> RANGE (got %s)",
                  dtl_strerror(rc));

            /* A valid stream whose expansion cannot fit out_cap. */
            {
                uint8_t enc8[32];
                size_t enc8_len = 0;
                uint8_t small[4];
                rc = lz77->encode((const uint8_t *)"AAAAAAAA", 8,
                                  enc8, sizeof enc8, &enc8_len);
                CHECK(rc == DTL_OK, "lz77 encode 8xA (got %s)", dtl_strerror(rc));
                rc = lz77->decode(enc8, enc8_len, small, sizeof small, &ol);
                CHECK(rc == DTL_ERR_RANGE, "decode match-past-cap -> RANGE (got %s)",
                      dtl_strerror(rc));
            }
        }
    }

    /* --- dict ------------------------------------------------------------ */
    printf("\n[dict id 4]\n");
    {
        static const uint8_t phrases[] = "abcdabcdabcdWXYZabcd"; /* repeated "abcd" */
        static const uint8_t mixed[] = "the quick brown fox jumps!";
        static const uint8_t tail[] = "0123456789";            /* 10 -> ragged block */

        roundtrip(dict, phrases, sizeof phrases - 1, "repeated phrases");
        roundtrip(dict, mixed, sizeof mixed - 1, "mixed");
        roundtrip(dict, tail, sizeof tail - 1, "ragged final block");
        roundtrip(dict, phrases, 0, "empty");

        {
            uint8_t out[64];
            size_t ol = 0;
            dtl_err rc;

            /* entry_count=1, one 1-byte phrase 'A', then token id 5 (>= count). */
            rc = dict->decode(
                (const uint8_t[]){ 0x01, 0x00, 0x01, 0x41, 0x05, 0x00 }, 6,
                out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_BADRECORD, "decode token-id-oob -> BADRECORD (got %s)",
                  dtl_strerror(rc));

            /* entry_count=2, but entry 0 claims 3 phrase bytes with only 1 present. */
            rc = dict->decode((const uint8_t[]){ 0x02, 0x00, 0x03, 0x41 }, 4,
                              out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_TRUNCATED, "decode truncated-table -> TRUNCATED (got %s)",
                  dtl_strerror(rc));

            /* entry_count=1, 4-byte phrase, one token -> 4 bytes, but out_cap is 2. */
            rc = dict->decode(
                (const uint8_t[]){ 0x01, 0x00, 0x04, 'a', 'b', 'c', 'd', 0x00, 0x00 },
                9, out, 2, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode phrase-past-cap -> RANGE (got %s)",
                  dtl_strerror(rc));
        }
    }

    /* --- delta ----------------------------------------------------------- */
    printf("\n[delta id 5]\n");
    {
        static const uint32_t ascending[]  = { 10, 11, 13, 16, 20, 25 };
        static const uint32_t descending[] = { 1000, 900, 800, 700, 0 };
        static const uint32_t wrapping[]   = { 0u, 0xFFFFFFFFu, 1u, 0xFFFFFFFEu, 7u };
        static const uint32_t single[]     = { 0x01020304u };
        uint8_t raw[64];
        size_t n;

        n = put_u32s(raw, ascending, sizeof ascending / sizeof ascending[0]);
        roundtrip(delta, raw, n, "ascending");
        n = put_u32s(raw, descending, sizeof descending / sizeof descending[0]);
        roundtrip(delta, raw, n, "descending");
        n = put_u32s(raw, wrapping, sizeof wrapping / sizeof wrapping[0]);
        roundtrip(delta, raw, n, "wrapping");
        n = put_u32s(raw, single, 1);
        roundtrip(delta, raw, n, "single value");
        roundtrip(delta, raw, 0, "empty");

        {
            uint8_t out[64];
            size_t ol = 0;
            dtl_err rc;

            /* First raw value present, then a varint with no terminator. */
            rc = delta->decode((const uint8_t[]){ 0x00, 0x00, 0x00, 0x00, 0x80 }, 5,
                               out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_TRUNCATED, "decode truncated-varint -> TRUNCATED (got %s)",
                  dtl_strerror(rc));

            /* First raw value needs 4 bytes but out_cap is 2. */
            rc = delta->decode((const uint8_t[]){ 0x00, 0x00, 0x00, 0x00 }, 4,
                               out, 2, &ol);
            CHECK(rc == DTL_ERR_RANGE, "decode first-value-past-cap -> RANGE (got %s)",
                  dtl_strerror(rc));

            /* Encode rejects a trailing partial u32. */
            rc = delta->encode((const uint8_t[]){ 0x01, 0x02, 0x03 }, 3,
                               out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_TRUNCATED, "encode partial-u32 -> TRUNCATED (got %s)",
                  dtl_strerror(rc));
        }
    }

    /* --- base32 ---------------------------------------------------------- */
    printf("\n[base32 id 6]\n");
    {
        uint8_t buf[16];
        size_t L;

        /* Lengths 0..10 exercise every padding case and multi-group input. */
        for (L = 0; L <= 10; L++) {
            char label[32];
            size_t k;
            for (k = 0; k < L; k++)
                buf[k] = (uint8_t)(k * 37u + 11u);
            snprintf(label, sizeof label, "len %zu (pad case)", L);
            roundtrip(base32, buf, L, label);
        }

        {
            uint8_t out[64];
            size_t ol = 0;
            dtl_err rc;

            /* '1' is not in the base32 alphabet. */
            rc = base32->decode((const uint8_t *)"AAAAAAA1", 8,
                                out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_BADRECORD, "decode bad-char -> BADRECORD (got %s)",
                  dtl_strerror(rc));

            /* Two padding characters is not a valid base32 padding count. */
            rc = base32->decode((const uint8_t *)"AAAAAA==", 8,
                                out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_BADRECORD, "decode bad-padding -> BADRECORD (got %s)",
                  dtl_strerror(rc));

            /* Length not a multiple of 8. */
            rc = base32->decode((const uint8_t *)"AAA", 3, out, sizeof out, &ol);
            CHECK(rc == DTL_ERR_TRUNCATED, "decode non-multiple-of-8 -> TRUNCATED (got %s)",
                  dtl_strerror(rc));

            /* A valid 5-byte group decodes to 5 bytes but out_cap is 2. */
            {
                uint8_t enc[8];
                size_t enc_len = 0;
                rc = base32->encode((const uint8_t *)"ABCDE", 5,
                                    enc, sizeof enc, &enc_len);
                CHECK(rc == DTL_OK, "base32 encode 5 bytes (got %s)", dtl_strerror(rc));
                rc = base32->decode(enc, enc_len, out, 2, &ol);
                CHECK(rc == DTL_ERR_RANGE, "decode past-cap -> RANGE (got %s)",
                      dtl_strerror(rc));
            }
        }
    }

    printf("\ncodec smoke: %s (%d failure%s)\n",
           g_failures == 0 ? "ok" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
