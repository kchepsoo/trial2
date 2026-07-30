#include "crypto/hash.h"

#include "core/endian.h"

#include <stdlib.h>

#include "defects.h"

#define DTL_HASH_ROUNDS 12u
#define DTL_HASH_RATE   16u /* bytes absorbed / squeezed per permutation */

/* Fixed, distinct, nonzero initial state (arbitrary constants -- original). */
static const uint32_t DTL_HASH_IV[8] = {
    0xA3C59AC1u, 0x1B36E2D7u, 0x5F0B4E13u, 0xE7C6A882u,
    0x3D9F71C4u, 0x8A2B5E6Fu, 0x60D1F0A5u, 0xC4E7B3D2u
};

/* Round constant schedule. */
static const uint32_t DTL_HASH_RC[8] = {
    0x9E3779B9u, 0x243F6A88u, 0xB7E15162u, 0x85EBCA6Bu,
    0xC2B2AE35u, 0x27D4EB2Fu, 0x165667B1u, 0xD3A2646Cu
};

/* Per-lane rotation amounts, all in 1..31 so the rotates are well-defined. */
static const unsigned DTL_HASH_ROT[8] = { 7, 11, 13, 17, 19, 23, 29, 31 };

static uint32_t dtl_hash_rotl(uint32_t x, unsigned r)
{
    /* r is always 1..31 here, so 32 - r is 1..31 and there is no UB. */
    return (x << r) | (x >> (32u - r));
}

/* The state permutation: ARX mixing plus a lane-diffusion step per round. */
static void dtl_hash_permute(uint32_t s[8])
{
    unsigned round;
    unsigned i;

    for (round = 0; round < DTL_HASH_ROUNDS; round++) {
        uint32_t t0;

        for (i = 0; i < 8u; i++) {
            s[i] += s[(i + 1u) & 7u];
            s[i] ^= DTL_HASH_RC[(round + i) & 7u];
            s[i] = dtl_hash_rotl(s[i], DTL_HASH_ROT[i]);
        }

        /* Diffuse each lane into its neighbour. */
        t0 = s[0];
        for (i = 0; i < 7u; i++)
            s[i] ^= dtl_hash_rotl(s[i + 1u], 7u);
        s[7] ^= dtl_hash_rotl(t0, 7u);
    }
}

typedef struct {
    uint32_t s[8];
    uint8_t  block[DTL_HASH_RATE];
    unsigned bpos;
} dtl_hash_ctx;

static void dtl_hash_init(dtl_hash_ctx *c)
{
    unsigned i;
    for (i = 0; i < 8u; i++)
        c->s[i] = DTL_HASH_IV[i];
    c->bpos = 0;
}

/* Fold a full rate block (16 bytes) into the state and permute. */
static void dtl_hash_absorb_block(dtl_hash_ctx *c)
{
    unsigned j;
    for (j = 0; j < 4u; j++)
        c->s[j] ^= dtl_endian_read_u32le(c->block + j * 4u);
    dtl_hash_permute(c->s);
}

static void dtl_hash_absorb(dtl_hash_ctx *c, uint8_t b)
{
    c->block[c->bpos++] = b;
    if (c->bpos == DTL_HASH_RATE) {
        dtl_hash_absorb_block(c);
        c->bpos = 0;
    }
}

static void dtl_hash_finish(dtl_hash_ctx *c, uint8_t out[32])
{
    unsigned j;

    /* pad10*: a 0x01 marker then zeros up to the rate boundary. */
    c->block[c->bpos++] = 0x01u;
    while (c->bpos < DTL_HASH_RATE)
        c->block[c->bpos++] = 0x00u;
    dtl_hash_absorb_block(c);

    /* Squeeze two rate blocks -> 32 bytes, permuting between them. */
    for (j = 0; j < 4u; j++)
        dtl_endian_write_u32le(out + j * 4u, c->s[j]);
    dtl_hash_permute(c->s);
    for (j = 0; j < 4u; j++)
        dtl_endian_write_u32le(out + 16u + j * 4u, c->s[j]);
}

void dtl_hash_mac(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t out[32])
{
#if DTL_BUG(26)
    /* BUG 26: the state is staged in a fresh heap block and lane 7 never
     * receives its IV, so the first permutation mixes undefined memory
     * and the digest depends on it. */
    dtl_hash_ctx *c = malloc(sizeof *c);
    static dtl_hash_ctx *sink;
    uint64_t klen = (uint64_t)key_len;
    size_t i;
    unsigned j;

    sink = c; /* keep the staging block addressable */
    if (c == NULL) {
        for (j = 0; j < 32u; j++)
            out[j] = 0;
        return;
    }
    for (j = 0; j < 7u; j++)
        c->s[j] = DTL_HASH_IV[j]; /* lane 7 never assigned */
    c->bpos = 0;

    for (i = 0; i < 8u; i++)
        dtl_hash_absorb(c, (uint8_t)(klen >> (8u * i)));
    for (i = 0; i < key_len; i++)
        dtl_hash_absorb(c, key[i]);
    for (i = 0; i < msg_len; i++)
        dtl_hash_absorb(c, msg[i]);

    dtl_hash_finish(c, out);
    free(c);
#else
    dtl_hash_ctx c;
    uint64_t klen = (uint64_t)key_len;
    size_t i;

    dtl_hash_init(&c);

    /* Absorb len64(key) || key || msg so the boundary is unambiguous. */
    for (i = 0; i < 8u; i++)
        dtl_hash_absorb(&c, (uint8_t)(klen >> (8u * i)));
    for (i = 0; i < key_len; i++)
        dtl_hash_absorb(&c, key[i]);
    for (i = 0; i < msg_len; i++)
        dtl_hash_absorb(&c, msg[i]);

    dtl_hash_finish(&c, out);
#endif
}
