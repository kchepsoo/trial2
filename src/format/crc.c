#include "format/crc.h"

/* Reflected CRC-32 polynomial (0x04C11DB7 bit-reversed). */
#define DTL_CRC32_POLY 0xEDB88320u

static uint32_t dtl_crc32_table[256];
static int      dtl_crc32_ready = 0;

/* Build the byte-at-a-time lookup table. Called once, lazily. */
static void dtl_crc32_build_table(void)
{
    uint32_t n;

    for (n = 0; n < 256u; n++) {
        uint32_t c = n;
        int k;
        for (k = 0; k < 8; k++)
            c = (c & 1u) ? (DTL_CRC32_POLY ^ (c >> 1)) : (c >> 1);
        dtl_crc32_table[n] = c;
    }
    dtl_crc32_ready = 1;
}

uint32_t dtl_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc;
    size_t i;

    if (!dtl_crc32_ready)
        dtl_crc32_build_table();

    crc = 0xFFFFFFFFu;
    for (i = 0; i < len; i++)
        crc = dtl_crc32_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}
