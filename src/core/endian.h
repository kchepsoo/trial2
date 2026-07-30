#ifndef DTL_CORE_ENDIAN_H
#define DTL_CORE_ENDIAN_H

#include <stdint.h>

/*
 * core/endian -- little-endian fixed-width load/store on raw byte pointers.
 *
 * The DTL wire format is little-endian. These helpers assemble and disassemble
 * integer values one byte at a time using shifts and masks, so they are free of
 * alignment and type-punning undefined behaviour and produce identical results
 * regardless of host byte order.
 *
 * Read helpers require the source pointer to address at least the corresponding
 * number of bytes (2/4/8); write helpers require the same of the destination.
 * Bounds are the caller's responsibility -- see core/buf for a checked reader.
 */

/* Loads: read a little-endian value from p[0..N-1]. */
uint16_t dtl_endian_read_u16le(const uint8_t *p);
uint32_t dtl_endian_read_u32le(const uint8_t *p);
uint64_t dtl_endian_read_u64le(const uint8_t *p);

/* Stores: write v to p[0..N-1] in little-endian order. */
void dtl_endian_write_u16le(uint8_t *p, uint16_t v);
void dtl_endian_write_u32le(uint8_t *p, uint32_t v);
void dtl_endian_write_u64le(uint8_t *p, uint64_t v);

#endif /* DTL_CORE_ENDIAN_H */
