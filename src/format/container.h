#ifndef DTL_FORMAT_CONTAINER_H
#define DTL_FORMAT_CONTAINER_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/buf.h"
#include "core/err.h"

/*
 * format/container -- the DTL (Device Telemetry Log) container, decode side.
 *
 * On-disk layout, all little-endian:
 *
 *   header (12 bytes)
 *     magic         u32   bytes 44 54 4C 01  ("DTL" + format generation byte)
 *     version       u8    (accepted: 1)
 *     flags         u8    (bit0 = has_hmac_trailer; all other bits reserved = 0)
 *     section_count u16
 *     header_crc    u32   CRC-32 over the 8 header bytes preceding this field
 *
 *   section table  (section_count entries, 16 bytes each)
 *     type      u16
 *     codec_id  u8    (0 = store/none)
 *     reserved  u8    (must be 0)
 *     raw_len   u32   (decompressed length)
 *     comp_len  u32   (compressed length, as stored in the blob region)
 *     offset    u32   (byte offset of this blob from the start of the blob region)
 *
 *   blob region    (concatenated section blobs; each comp_len bytes at its offset)
 *
 *   hmac trailer   (present only if flags.has_hmac_trailer: exactly 32 bytes)
 *
 * Parsing is zero-copy: section blob pointers and the hmac pointer refer back
 * into the caller's input buffer. The parsed section array is allocated from a
 * caller-supplied arena. The HMAC is carried, not verified (crypto/ later).
 */

/* Magic as a little-endian u32 of the on-disk bytes 44 54 4C 01. */
#define DTL_MAGIC 0x014C5444u

/* The only container version accepted right now. */
#define DTL_VERSION 1u

/* flags bit definitions. */
#define DTL_FLAG_HAS_HMAC 0x01u
#define DTL_FLAGS_KNOWN   (DTL_FLAG_HAS_HMAC)

/* Size of the HMAC trailer in bytes, when present. */
#define DTL_HMAC_LEN 32u

/* Upper bound on a section's decompressed length (sanity cap): 64 MiB. */
#define DTL_SECTION_MAX_RAW (64u * 1024u * 1024u)

typedef struct dtl_section {
    uint16_t       type;      /* section type id                              */
    uint8_t        codec_id;  /* codec used for this blob (0 = store)         */
    uint32_t       raw_len;   /* decompressed length                          */
    uint32_t       comp_len;  /* stored (compressed) length in the blob region*/
    uint32_t       offset;    /* offset of blob within the blob region        */
    const uint8_t *blob;      /* -> comp_len bytes inside the input buffer    */
} dtl_section;

typedef struct dtl_container {
    uint8_t        version;
    uint8_t        flags;
    uint16_t       section_count;
    dtl_section   *sections;   /* arena-allocated array, or NULL if count == 0 */
    const uint8_t *hmac;       /* NULL, or -> DTL_HMAC_LEN bytes in the input   */
} dtl_container;

/*
 * dtl_container_parse -- decode a whole container from b, positioned at its
 * start. On success returns DTL_OK and fills *out; section blob pointers and
 * out->hmac point into b's underlying buffer. The section array is allocated
 * from a. On any failure a specific dtl_err is returned and *out is left
 * unspecified; no bytes outside the input are ever read.
 *
 * Error codes: DTL_ERR_TRUNCATED (input too short), DTL_ERR_BADMAGIC,
 * DTL_ERR_BADVERSION, DTL_ERR_BADHEADER (crc mismatch or reserved flag bits),
 * DTL_ERR_BADRECORD (reserved section byte nonzero), DTL_ERR_RANGE (a section's
 * lengths/offset do not fit the blob region), DTL_ERR_OOM (arena exhausted).
 */
dtl_err dtl_container_parse(dtl_buf *b, dtl_arena *a, dtl_container *out);

#endif /* DTL_FORMAT_CONTAINER_H */
