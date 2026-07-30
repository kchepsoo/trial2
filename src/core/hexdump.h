#ifndef DTL_CORE_HEXDUMP_H
#define DTL_CORE_HEXDUMP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * core/hexdump -- human-readable hex/ASCII dump for debugging.
 *
 * dtl_hexdump writes a classic 16-bytes-per-row view of [data, data+len) to the
 * given stream: an 8-digit hex offset, the row's bytes in hex (grouped 8 + 8),
 * then the printable-ASCII rendering with non-printables shown as '.'. A len of
 * 0 produces no output. data may be NULL only when len is 0.
 */
void dtl_hexdump(FILE *out, const uint8_t *data, size_t len);

#endif /* DTL_CORE_HEXDUMP_H */
