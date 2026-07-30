#include "writer/writer.h"

#include <stdlib.h>
#include <string.h>

#include "codec/registry.h"
#include "core/endian.h"
#include "crypto/hash.h"
#include "format/container.h"
#include "format/crc.h"

/* ---- growable TLV accumulator (arena-backed) --------------------------- */

/* Ensure the current TLV buffer has room for `need` more bytes. */
static int dtl_writer_reserve(dtl_writer *w, size_t need)
{
    size_t want;
    size_t newcap;
    uint8_t *nd;

    if (w->err != DTL_OK)
        return 0;
    if (w->tlv_cap - w->tlv_len >= need)
        return 1;

    want = w->tlv_len + need;
    if (want < w->tlv_len) { /* size_t overflow */
        w->err = DTL_ERR_RANGE;
        return 0;
    }
    newcap = w->tlv_cap ? w->tlv_cap : 64;
    while (newcap < want) {
        if (newcap > SIZE_MAX / 2) {
            w->err = DTL_ERR_OOM;
            return 0;
        }
        newcap *= 2;
    }
    nd = dtl_arena_alloc(w->arena, newcap);
    if (nd == NULL) {
        w->err = DTL_ERR_OOM;
        return 0;
    }
    if (w->tlv_len != 0)
        memcpy(nd, w->tlv, w->tlv_len);
    w->tlv = nd;
    w->tlv_cap = newcap;
    return 1;
}

static void dtl_writer_u8(dtl_writer *w, uint8_t v)
{
    if (!dtl_writer_reserve(w, 1))
        return;
    w->tlv[w->tlv_len++] = v;
}

static void dtl_writer_u16(dtl_writer *w, uint16_t v)
{
    if (!dtl_writer_reserve(w, 2))
        return;
    dtl_endian_write_u16le(w->tlv + w->tlv_len, v);
    w->tlv_len += 2;
}

static void dtl_writer_u32(dtl_writer *w, uint32_t v)
{
    if (!dtl_writer_reserve(w, 4))
        return;
    dtl_endian_write_u32le(w->tlv + w->tlv_len, v);
    w->tlv_len += 4;
}

static void dtl_writer_bytes(dtl_writer *w, const uint8_t *s, size_t n)
{
    if (!dtl_writer_reserve(w, n))
        return;
    if (n != 0)
        memcpy(w->tlv + w->tlv_len, s, n);
    w->tlv_len += n;
}

/* ---- per-type payload encoders (inverse of records/ parsing) ----------- */

static void dtl_writer_payload(dtl_writer *w, const dtl_record *rec)
{
    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        dtl_writer_u32(w, rec->u.heartbeat.uptime_s);
        dtl_writer_u32(w, rec->u.heartbeat.seq);
        break;
    case DTL_REC_GEO:
        dtl_writer_u32(w, (uint32_t)rec->u.geo.lat_e7);
        dtl_writer_u32(w, (uint32_t)rec->u.geo.lon_e7);
        dtl_writer_u32(w, (uint32_t)rec->u.geo.alt_mm);
        break;
    case DTL_REC_BATTERY:
        dtl_writer_u8(w, rec->u.battery.pct);
        dtl_writer_u16(w, (uint16_t)rec->u.battery.temp_c_e1);
        dtl_writer_u32(w, rec->u.battery.cycles);
        break;
    case DTL_REC_NET:
        dtl_writer_u8(w, rec->u.net.iface_id);
        dtl_writer_u32(w, rec->u.net.rx_bytes);
        dtl_writer_u32(w, rec->u.net.tx_bytes);
        dtl_writer_u32(w, rec->u.net.rx_pkts);
        dtl_writer_u32(w, rec->u.net.tx_pkts);
        break;
    case DTL_REC_FIRMWARE:
        dtl_writer_u16(w, rec->u.firmware.major);
        dtl_writer_u16(w, rec->u.firmware.minor);
        dtl_writer_u16(w, rec->u.firmware.patch);
        dtl_writer_bytes(w, rec->u.firmware.hash, 8);
        break;
    case DTL_REC_SENSOR: {
        uint8_t i;
        dtl_writer_u16(w, rec->u.sensor.sensor_id);
        dtl_writer_u8(w, rec->u.sensor.count);
        for (i = 0; i < rec->u.sensor.count; i++) {
            uint32_t bits;
            memcpy(&bits, &rec->u.sensor.samples[i], sizeof bits);
            dtl_writer_u32(w, bits);
        }
        break;
    }
    case DTL_REC_EVENT:
        dtl_writer_u16(w, rec->u.event.code);
        dtl_writer_u16(w, rec->u.event.payload_len);
        dtl_writer_bytes(w, rec->u.event.payload, rec->u.event.payload_len);
        break;
    case DTL_REC_LOG:
        dtl_writer_u8(w, rec->u.log.severity);
        dtl_writer_u16(w, rec->u.log.msg_len);
        dtl_writer_bytes(w, (const uint8_t *)rec->u.log.msg, rec->u.log.msg_len);
        break;
    case DTL_REC_CONFIG: {
        uint8_t i;
        dtl_writer_u8(w, rec->u.config.pair_count);
        for (i = 0; i < rec->u.config.pair_count; i++) {
            const char *k = rec->u.config.pairs[i].key;
            const char *v = rec->u.config.pairs[i].value;
            size_t kn = strlen(k);
            size_t vn = strlen(v);
            if (kn > 0xFF || vn > 0xFF) {
                w->err = DTL_ERR_RANGE;
                return;
            }
            dtl_writer_u8(w, (uint8_t)kn);
            dtl_writer_bytes(w, (const uint8_t *)k, kn);
            dtl_writer_u8(w, (uint8_t)vn);
            dtl_writer_bytes(w, (const uint8_t *)v, vn);
        }
        break;
    }
    case DTL_REC_KEYREF:
        dtl_writer_u8(w, rec->u.keyref.slot_id);
        dtl_writer_u8(w, rec->u.keyref.label_len);
        dtl_writer_bytes(w, (const uint8_t *)rec->u.keyref.label,
                         rec->u.keyref.label_len);
        break;
    case DTL_REC_DIAG:
        dtl_writer_u16(w, rec->u.diag.subsystem);
        dtl_writer_u16(w, rec->u.diag.blob_len);
        dtl_writer_bytes(w, rec->u.diag.blob, rec->u.diag.blob_len);
        break;
    default:
        w->err = DTL_ERR_BADRECORD;
        break;
    }
}

/* ---- public API -------------------------------------------------------- */

void dtl_writer_init(dtl_writer *w, dtl_arena *a)
{
    w->arena = a;
    w->nsections = 0;
    w->in_section = 0;
    w->cur_type = 0;
    w->cur_codec = 0;
    w->tlv = NULL;
    w->tlv_len = 0;
    w->tlv_cap = 0;
    w->has_hmac = 0;
    w->hmac_key = NULL;
    w->hmac_key_len = 0;
    w->err = DTL_OK;
}

int dtl_writer_begin_section(dtl_writer *w, uint16_t type, uint8_t codec_id)
{
    if (w->err != DTL_OK)
        return -1;
    if (w->in_section) {
        w->err = DTL_ERR_INVAL;
        return -1;
    }
    if (w->nsections >= DTL_WRITER_MAX_SECTIONS) {
        w->err = DTL_ERR_RANGE;
        return -1;
    }
    w->in_section = 1;
    w->cur_type = type;
    w->cur_codec = codec_id;
    w->tlv_len = 0; /* reuse the accumulator buffer */
    return (int)w->nsections;
}

/* Append a complete TLV item: tag, u16 length, payload. */
static dtl_err dtl_writer_emit_tlv(dtl_writer *w, uint8_t tag,
                                   const dtl_record *rec,
                                   const uint8_t *raw_payload, uint16_t raw_len)
{
    size_t len_off;
    size_t payload_start;
    size_t plen;

    if (w->err != DTL_OK)
        return w->err;
    if (!w->in_section) {
        w->err = DTL_ERR_INVAL;
        return w->err;
    }

    dtl_writer_u8(w, tag);
    len_off = w->tlv_len;
    dtl_writer_u16(w, 0); /* length placeholder, patched below */
    payload_start = w->tlv_len;

    if (rec != NULL)
        dtl_writer_payload(w, rec);
    else
        dtl_writer_bytes(w, raw_payload, raw_len);

    if (w->err != DTL_OK)
        return w->err;

    plen = w->tlv_len - payload_start;
    if (plen > 0xFFFF) {
        w->err = DTL_ERR_RANGE;
        return w->err;
    }
    dtl_endian_write_u16le(w->tlv + len_off, (uint16_t)plen);
    return DTL_OK;
}

dtl_err dtl_writer_add_u32_batch(dtl_writer *w, uint8_t tag,
                                 const uint32_t *vals, uint32_t count)
{
    uint32_t i;

    if (w->err != DTL_OK)
        return w->err;

    /* The u16 length prefix caps the payload at 0xFFFF bytes. */
    if (count > 0xFFFFu / 4u) {
        w->err = DTL_ERR_RANGE;
        return w->err;
    }
    {
        size_t bytes = (size_t)count * 4u;
        uint8_t *staging = dtl_arena_alloc(w->arena, bytes);

        if (staging == NULL) {
            w->err = DTL_ERR_OOM;
            return w->err;
        }
        for (i = 0; i < count; i++)
            dtl_endian_write_u32le(staging + 4u * i, vals[i]);
        return dtl_writer_emit_tlv(w, tag, NULL, staging, (uint16_t)bytes);
    }
}

dtl_err dtl_writer_add_record(dtl_writer *w, const dtl_record *rec)
{
    return dtl_writer_emit_tlv(w, rec->tag, rec, NULL, 0);
}

dtl_err dtl_writer_add_raw_tlv(dtl_writer *w, uint8_t tag,
                               const uint8_t *payload, uint16_t len)
{
    return dtl_writer_emit_tlv(w, tag, NULL, payload, len);
}

dtl_err dtl_writer_end_section(dtl_writer *w)
{
    const dtl_codec *codec;
    size_t raw_len;
    size_t cap;
    uint8_t *out;
    size_t comp_len = 0;
    dtl_wsection *sec;

    if (w->err != DTL_OK)
        return w->err;
    if (!w->in_section) {
        w->err = DTL_ERR_INVAL;
        return w->err;
    }

    raw_len = w->tlv_len;
    /* Sections must be non-empty and within the container's sanity cap so the
     * emitted table passes dtl_container_parse. */
    if (raw_len == 0 || raw_len > DTL_SECTION_MAX_RAW) {
        w->err = DTL_ERR_RANGE;
        return w->err;
    }

    codec = dtl_codec_get(w->cur_codec);
    if (codec == NULL) {
        w->err = DTL_ERR_BADRECORD;
        return w->err;
    }

    /* Compress into an arena buffer, growing the output cap on RANGE. */
    cap = raw_len + raw_len / 2 + 64;
    for (;;) {
        dtl_err rc;
        out = dtl_arena_alloc(w->arena, cap);
        if (out == NULL) {
            w->err = DTL_ERR_OOM;
            return w->err;
        }
        rc = codec->encode(w->tlv, raw_len, out, cap, &comp_len);
        if (rc == DTL_OK)
            break;
        if (rc == DTL_ERR_RANGE && cap <= DTL_SECTION_MAX_RAW * 2) {
            cap = cap * 2 + 64;
            continue;
        }
        w->err = rc;
        return w->err;
    }

    if (comp_len > 0xFFFFFFFFu) {
        w->err = DTL_ERR_RANGE;
        return w->err;
    }

    sec = &w->sections[w->nsections];
    sec->type = w->cur_type;
    sec->codec_id = w->cur_codec;
    sec->raw_len = (uint32_t)raw_len;
    sec->comp_len = (uint32_t)comp_len;
    sec->blob = out;
    w->nsections++;
    w->in_section = 0;
    return DTL_OK;
}

dtl_err dtl_writer_set_hmac(dtl_writer *w, const uint8_t *key, size_t key_len)
{
    if (w->err != DTL_OK)
        return w->err;
    w->has_hmac = 1;
    w->hmac_key = key;
    w->hmac_key_len = key_len;
    return DTL_OK;
}

dtl_err dtl_writer_finish(dtl_writer *w, uint8_t **out, size_t *out_len)
{
    size_t header_size = 12;
    size_t table_size;
    size_t blob_region = 0;
    size_t hmac_size;
    size_t total;
    size_t i;
    size_t tpos;
    size_t bpos;
    size_t acc;
    uint8_t *buf;
    uint32_t crc;

    if (w->err != DTL_OK)
        return w->err;
    if (w->in_section) {
        w->err = DTL_ERR_INVAL; /* a section was left open */
        return w->err;
    }

    table_size = w->nsections * 16u;
    for (i = 0; i < w->nsections; i++)
        blob_region += w->sections[i].comp_len;

    /* The blob region offset field is u32; guard the cumulative size. */
    if (blob_region > 0xFFFFFFFFu) {
        w->err = DTL_ERR_RANGE;
        return w->err;
    }

    hmac_size = w->has_hmac ? DTL_HMAC_LEN : 0;
    total = header_size + table_size + blob_region + hmac_size;

    buf = dtl_arena_alloc(w->arena, total);
    if (buf == NULL) {
        w->err = DTL_ERR_OOM;
        return w->err;
    }

    /* Header (12 bytes). */
    buf[0] = 0x44; buf[1] = 0x54; buf[2] = 0x4C; buf[3] = 0x01; /* "DTL\1" */
    buf[4] = (uint8_t)DTL_VERSION;
    buf[5] = (uint8_t)(w->has_hmac ? DTL_FLAG_HAS_HMAC : 0u);
    dtl_endian_write_u16le(buf + 6, (uint16_t)w->nsections);
    crc = dtl_crc32(buf, 8); /* over magic..section_count */
    dtl_endian_write_u32le(buf + 8, crc);

    /* Section table, then the blob region. Offsets are cumulative comp_len. */
    tpos = header_size;
    acc = 0;
    for (i = 0; i < w->nsections; i++) {
        dtl_wsection *s = &w->sections[i];
        dtl_endian_write_u16le(buf + tpos, s->type); tpos += 2;
        buf[tpos++] = s->codec_id;
        buf[tpos++] = 0; /* reserved */
        dtl_endian_write_u32le(buf + tpos, s->raw_len);  tpos += 4;
        dtl_endian_write_u32le(buf + tpos, s->comp_len); tpos += 4;
        dtl_endian_write_u32le(buf + tpos, (uint32_t)acc); tpos += 4;
        acc += s->comp_len;
    }

    bpos = header_size + table_size;
    acc = 0;
    for (i = 0; i < w->nsections; i++) {
        dtl_wsection *s = &w->sections[i];
        if (s->comp_len != 0)
            memcpy(buf + bpos + acc, s->blob, s->comp_len);
        acc += s->comp_len;
    }

    if (w->has_hmac)
        dtl_hash_mac(w->hmac_key, w->hmac_key_len, buf, total - DTL_HMAC_LEN,
                     buf + total - DTL_HMAC_LEN);

    *out = buf;
    *out_len = total;
    return DTL_OK;
}
