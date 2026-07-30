/*
 * _smoke.c -- throwaway exerciser for the core module.
 *
 * Not part of any library. It calls each core primitive once over known-good
 * inputs so the three build configs (plain / asan / msan) have something to run.
 * On correct code it must produce no sanitizer reports, so every byte that is
 * later read (including arena-allocated memory) is initialised first.
 *
 * This file is deliberately temporary and will be removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "core/buf.h"
#include "core/endian.h"
#include "core/err.h"
#include "core/hexdump.h"

int main(void)
{
    /* --- endian round-trip ------------------------------------------------ */
    {
        uint8_t scratch[8];
        dtl_endian_write_u32le(scratch, 0xdeadbeefu);
        printf("endian: wrote 0xdeadbeef -> read 0x%08x\n",
               dtl_endian_read_u32le(scratch));
    }

    /* --- bounded reader --------------------------------------------------- */
    {
        static const uint8_t bytes[] = {
            0x11,                                           /* u8  */
            0x22, 0x33,                                     /* u16 */
            0x44, 0x55, 0x66, 0x77,                         /* u32 */
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* u64 */
            'D', 'T', 'L', '!'                              /* tail bytes */
        };
        dtl_buf b;
        uint8_t v8 = 0;
        uint16_t v16 = 0;
        uint32_t v32 = 0;
        uint64_t v64 = 0;
        uint8_t tail[4] = {0};
        int any_err = 0;
        dtl_err rc;

        dtl_buf_init(&b, bytes, sizeof bytes);
        printf("buf: remaining at start = %zu\n", dtl_buf_remaining(&b));

        any_err |= (dtl_buf_read_u8(&b, &v8) != DTL_OK);
        any_err |= (dtl_buf_read_u16(&b, &v16) != DTL_OK);
        any_err |= (dtl_buf_read_u32(&b, &v32) != DTL_OK);
        any_err |= (dtl_buf_read_u64(&b, &v64) != DTL_OK);
        any_err |= (dtl_buf_read_bytes(&b, tail, sizeof tail) != DTL_OK);
        printf("buf: reads %s u8=0x%02x u16=0x%04x u32=0x%08x u64=0x%016llx tail=%.4s\n",
               any_err ? "FAILED" : "ok",
               v8, v16, v32, (unsigned long long)v64, (const char *)tail);
        printf("buf: remaining at end = %zu\n", dtl_buf_remaining(&b));

        /* A read past the end must report truncation and consume nothing. */
        rc = dtl_buf_read_u8(&b, &v8);
        printf("buf: over-read rc=%s (remaining still %zu)\n",
               dtl_strerror(rc), dtl_buf_remaining(&b));
    }

    /* --- arena ------------------------------------------------------------ */
    {
        dtl_arena arena;
        /* Small default block so a handful of allocs forces a second block and
         * exercises the descriptor-array realloc path. */
        dtl_arena_init(&arena, 32);

        char *a = dtl_arena_alloc(&arena, 8);
        char *b = dtl_arena_alloc(&arena, 24);
        char *c = dtl_arena_alloc(&arena, 40); /* larger than block_size */

        if (a == NULL || b == NULL || c == NULL) {
            fprintf(stderr, "arena: %s\n", dtl_strerror(DTL_ERR_OOM));
            return 1;
        }

        /* Initialise before dumping so msan sees defined bytes. */
        memcpy(a, "arena-A!", 8);
        memset(b, 'B', 24);
        memset(c, 'C', 40);

        printf("arena: three allocations, hexdump of first block:\n");
        dtl_hexdump(stdout, (const uint8_t *)a, 8);
        dtl_hexdump(stdout, (const uint8_t *)b, 24);

        dtl_arena_reset(&arena);
        /* Reuse after reset to prove blocks are recycled. */
        char *d = dtl_arena_alloc(&arena, 16);
        if (d != NULL) {
            memset(d, 'D', 16);
            printf("arena: after reset, hexdump of reused block:\n");
            dtl_hexdump(stdout, (const uint8_t *)d, 16);
        }

        dtl_arena_free(&arena);
    }

    /* --- err -------------------------------------------------------------- */
    printf("err: DTL_OK=\"%s\" RANGE=\"%s\" OOM=\"%s\" unknown=\"%s\"\n",
           dtl_strerror(DTL_OK), dtl_strerror(DTL_ERR_RANGE),
           dtl_strerror(DTL_ERR_OOM), dtl_strerror((dtl_err)999));

    printf("smoke: ok\n");
    return 0;
}
