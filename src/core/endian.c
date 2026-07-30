#include "core/endian.h"

/*
 * All values are built by widening each byte to the result type and shifting it
 * into place. No pointer casts, no memcpy-onto-a-wider-type, no dependence on
 * host endianness.
 */

uint16_t dtl_endian_read_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0]
                    | (uint16_t)((uint16_t)p[1] << 8));
}

uint32_t dtl_endian_read_u32le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

uint64_t dtl_endian_read_u64le(const uint8_t *p)
{
    return (uint64_t)p[0]
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

void dtl_endian_write_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}

void dtl_endian_write_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

void dtl_endian_write_u64le(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
    p[4] = (uint8_t)((v >> 32) & 0xff);
    p[5] = (uint8_t)((v >> 40) & 0xff);
    p[6] = (uint8_t)((v >> 48) & 0xff);
    p[7] = (uint8_t)((v >> 56) & 0xff);
}
