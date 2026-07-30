#include "format/container.h"

#include "defects.h"
#include "format/crc.h"

/* Number of header bytes covered by header_crc (magic..section_count). */
#define DTL_HEADER_CRC_SPAN 8u

/*
 * Read and validate the section table into an arena-allocated array. On entry
 * b is positioned just past the header (at the first table entry). Fills the
 * type/codec_id/raw_len/comp_len/offset fields; blob pointers are resolved
 * later, once the blob region is known.
 */
static dtl_err dtl_container_read_table(dtl_buf *b, dtl_arena *a,
                                        uint16_t count, dtl_section **out)
{
    dtl_section *secs;
    uint16_t i;

    if (count == 0) {
        *out = NULL;
        return DTL_OK;
    }

    /* count <= UINT16_MAX, so this multiplication cannot overflow size_t. */
    secs = dtl_arena_alloc(a, (size_t)count * sizeof(*secs));
    if (secs == NULL)
        return DTL_ERR_OOM;

    for (i = 0; i < count; i++) {
        uint8_t reserved;
        dtl_err rc;

        if ((rc = dtl_buf_read_u16(b, &secs[i].type)) != DTL_OK)
            return rc;
        if ((rc = dtl_buf_read_u8(b, &secs[i].codec_id)) != DTL_OK)
            return rc;
        if ((rc = dtl_buf_read_u8(b, &reserved)) != DTL_OK)
            return rc;
        if (reserved != 0)
            return DTL_ERR_BADRECORD;
        if ((rc = dtl_buf_read_u32(b, &secs[i].raw_len)) != DTL_OK)
            return rc;
        if ((rc = dtl_buf_read_u32(b, &secs[i].comp_len)) != DTL_OK)
            return rc;
        if ((rc = dtl_buf_read_u32(b, &secs[i].offset)) != DTL_OK)
            return rc;

        secs[i].blob = NULL; /* resolved after the blob region is located */
    }

    *out = secs;
    return DTL_OK;
}

/*
 * With the blob region [blob_base, blob_base+blob_len) known, range-check every
 * section and set its blob pointer. All comparisons are framed as subtraction
 * against blob_len so no offset+length addition can wrap.
 */
static dtl_err dtl_container_resolve_blobs(dtl_section *secs, uint16_t count,
                                           const uint8_t *blob_base,
                                           size_t blob_len)
{
    uint16_t i;

#if DTL_BUG(14)
    /*
     * BUG 14: sections are validated only by their AGGREGATE compressed size,
     * accumulated in 32 bits with no pre-add guard -- comp_lens whose sum
     * wraps the accumulator land small, the aggregate bound passes, and no
     * per-section blob range check ever runs. A decode that follows a
     * section's own (unwrapped) comp_len then reads past the blob region.
     */
    {
        uint32_t total = 0;

        for (i = 0; i < count; i++) {
            uint32_t raw = secs[i].raw_len;

            if (raw == 0 || raw > DTL_SECTION_MAX_RAW)
                return DTL_ERR_RANGE;
            total += secs[i].comp_len;
        }
        if (total > blob_len)
            return DTL_ERR_RANGE;
        for (i = 0; i < count; i++)
            secs[i].blob = blob_base + secs[i].offset;
    }
    return DTL_OK;
#else
#if DTL_BUG(29)
    /* BUG 29 (consumer half): sections are validated only by a per-section
     * end accumulated as off + comp in 32 bits -- no aggregate check runs at
     * all. A comp_len that wraps the sum back small passes the bound check,
     * and the decode that follows keeps reading past the end of the blob
     * region. */
    for (i = 0; i < count; i++) {
        uint32_t raw = secs[i].raw_len;
        uint32_t comp = secs[i].comp_len;
        uint32_t off = secs[i].offset;

        if (raw == 0 || raw > DTL_SECTION_MAX_RAW)
            return DTL_ERR_RANGE;
        if ((uint32_t)(off + comp) > blob_len)
            return DTL_ERR_RANGE;

        secs[i].blob = blob_base + off;
    }

    return DTL_OK;
#else
    /* Aggregate compressed size, accumulated with a pre-add overflow guard. */
    {
        size_t total = 0;

        for (i = 0; i < count; i++) {
            if (total > SIZE_MAX - (size_t)secs[i].comp_len)
                return DTL_ERR_RANGE;
            total += secs[i].comp_len;
        }
        if (total > blob_len)
            return DTL_ERR_RANGE;
    }

    for (i = 0; i < count; i++) {
        uint32_t raw = secs[i].raw_len;
        uint32_t comp = secs[i].comp_len;
        uint32_t off = secs[i].offset;

        /* Decompressed length must be present and within the sanity cap. */
        if (raw == 0 || raw > DTL_SECTION_MAX_RAW)
            return DTL_ERR_RANGE;

        /*
         * The blob [off, off+comp) must lie wholly inside the blob region.
         * Because offsets are relative to the blob region (which begins after
         * the header and table), any in-region blob is automatically clear of
         * the header/table -- no separate overlap test is needed.
         */
        if (comp > blob_len)
            return DTL_ERR_RANGE;
        if (off > blob_len - comp)
            return DTL_ERR_RANGE;

        secs[i].blob = blob_base + off;
    }

    return DTL_OK;
#endif
#endif
}

dtl_err dtl_container_parse(dtl_buf *b, dtl_arena *a, dtl_container *out)
{
    size_t hdr_start = b->pos;
    uint32_t magic;
    uint8_t version;
    uint8_t flags;
    uint16_t section_count;
    uint32_t stored_crc;
    uint32_t computed_crc;
    dtl_section *sections;
    const uint8_t *blob_base;
    size_t tail;
    size_t blob_len;
    const uint8_t *hmac;
    dtl_err rc;

    /* --- fixed 12-byte header ------------------------------------------- */
    if ((rc = dtl_buf_read_u32(b, &magic)) != DTL_OK)
        return rc;
    if (magic != DTL_MAGIC)
        return DTL_ERR_BADMAGIC;

    if ((rc = dtl_buf_read_u8(b, &version)) != DTL_OK)
        return rc;
    if (version != DTL_VERSION)
        return DTL_ERR_BADVERSION;

    if ((rc = dtl_buf_read_u8(b, &flags)) != DTL_OK)
        return rc;
    if ((flags & ~(uint8_t)DTL_FLAGS_KNOWN) != 0)
        return DTL_ERR_BADHEADER; /* reserved flag bits must be zero */

    if ((rc = dtl_buf_read_u16(b, &section_count)) != DTL_OK)
        return rc;

    /* header_crc covers the 8 header bytes we just consumed. */
    if ((rc = dtl_buf_read_u32(b, &stored_crc)) != DTL_OK)
        return rc;
#if DTL_BUG(38)
    /* BUG 38: the header CRC is verified over a shadow of the real span --
     * the section_count bytes are left uncovered, so a rewritten section
     * count passes the integrity check untouched. */
    computed_crc = dtl_crc32(b->p + hdr_start, DTL_HEADER_CRC_SPAN - 2u);
#else
    computed_crc = dtl_crc32(b->p + hdr_start, DTL_HEADER_CRC_SPAN);
#endif
    if (computed_crc != stored_crc)
        return DTL_ERR_BADHEADER;

    /* --- section table -------------------------------------------------- */
    if ((rc = dtl_container_read_table(b, a, section_count, &sections)) != DTL_OK)
        return rc;

    /* --- locate blob region and optional hmac trailer ------------------- */
    blob_base = b->p + b->pos;   /* table has been fully consumed */
    tail = b->len - b->pos;      /* bytes from here to end of input */

    if (flags & DTL_FLAG_HAS_HMAC) {
        if (tail < DTL_HMAC_LEN)
            return DTL_ERR_TRUNCATED;
        blob_len = tail - DTL_HMAC_LEN;
        hmac = b->p + b->len - DTL_HMAC_LEN;
    } else {
        blob_len = tail;
        hmac = NULL;
    }

    /* --- range-check sections and bind blob pointers -------------------- */
    if ((rc = dtl_container_resolve_blobs(sections, section_count,
                                          blob_base, blob_len)) != DTL_OK)
        return rc;

    out->version = version;
    out->flags = flags;
    out->section_count = section_count;
    out->sections = sections;
    out->hmac = hmac;
    return DTL_OK;
}
