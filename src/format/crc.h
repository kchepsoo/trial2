#ifndef DTL_FORMAT_CRC_H
#define DTL_FORMAT_CRC_H

#include <stddef.h>
#include <stdint.h>

/*
 * format/crc -- CRC-32 (IEEE 802.3) over a byte range.
 *
 * Standard reflected algorithm with polynomial 0xEDB88320, initial value all-
 * ones, and a final XOR of all-ones -- the same CRC-32 used by zlib/gzip/PNG.
 * The 256-entry lookup table is built once on first use. Used by the container
 * parser to validate header_crc.
 */
uint32_t dtl_crc32(const uint8_t *data, size_t len);

#endif /* DTL_FORMAT_CRC_H */
