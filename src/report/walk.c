#include "report/walk.h"

#include <stdio.h>
#include <stdlib.h>

#include "codec/registry.h"
#include "core/buf.h"
#include "format/container.h"
#include "format/tlv.h"
#include "records/event.h"
#include "records/registry.h"

#define DTL_WALK_DEFAULT_MAX_DECODE (16u * 1024u * 1024u)

const char *dtl_walk_tag_name(uint8_t tag)
{
    switch (tag) {
    case DTL_REC_HEARTBEAT: return "HEARTBEAT";
    case DTL_REC_SENSOR:    return "SENSOR";
    case DTL_REC_EVENT:     return "EVENT";
    case DTL_REC_DIAG:      return "DIAG";
    case DTL_REC_GEO:       return "GEO";
    case DTL_REC_BATTERY:   return "BATTERY";
    case DTL_REC_NET:       return "NET";
    case DTL_REC_LOG:       return "LOG";
    case DTL_REC_CONFIG:    return "CONFIG";
    case DTL_REC_KEYREF:    return "KEYREF";
    case DTL_REC_FIRMWARE:  return "FIRMWARE";
    default:                return "UNKNOWN";
    }
}

static void dtl_walk_report_error(const dtl_walk *w, uint16_t section_index,
                                  size_t record_in_sec, dtl_err rc, int fatal)
{
    if (w->on_error != NULL) {
        dtl_walk_error we;
        we.section_index = section_index;
        we.record_in_sec = record_in_sec;
        we.rc = rc;
        we.fatal = fatal;
        w->on_error(&we, w->user);
    }
}

dtl_err dtl_walk_memory(const uint8_t *data, size_t len, dtl_arena *a,
                        const dtl_walk *w)
{
    dtl_buf in;
    dtl_container cont;
    dtl_err rc;
    size_t max_decode;
    size_t record_index = 0;
    uint16_t si;

    if (w == NULL || w->on_record == NULL)
        return DTL_ERR_INVAL;

    dtl_buf_init(&in, data, len);
    rc = dtl_container_parse(&in, a, &cont);
    if (rc != DTL_OK)
        return rc;

    max_decode = w->max_decode ? w->max_decode : DTL_WALK_DEFAULT_MAX_DECODE;

    for (si = 0; si < cont.section_count; si++) {
        const dtl_section *sec = &cont.sections[si];
        const dtl_codec *codec = dtl_codec_get(sec->codec_id);
        uint8_t *raw;
        size_t got = 0;
        size_t record_in_sec = 0;

        if (codec == NULL) {
            dtl_walk_report_error(w, si, 0, DTL_ERR_BADRECORD, 1);
            continue;
        }
        if (sec->raw_len > max_decode) {
            dtl_walk_report_error(w, si, 0, DTL_ERR_RANGE, 1);
            continue;
        }

        raw = dtl_arena_alloc(a, sec->raw_len ? sec->raw_len : 1);
        if (raw == NULL)
            return DTL_ERR_OOM;

        rc = codec->decode(sec->blob, sec->comp_len, raw, sec->raw_len, &got);
        if (rc != DTL_OK) {
            dtl_walk_report_error(w, si, 0, rc, 1);
            continue;
        }

        {
            dtl_buf stream;
            dtl_tlv tlv;

            dtl_buf_init(&stream, raw, got);
            for (;;) {
                dtl_record rec;
                dtl_walk_event ev;

                rc = dtl_tlv_next(&stream, &tlv);
                if (rc != DTL_OK) {
                    /* TRUNCATED at a clean stream end means "no more
                     * records"; mid-stream it is reported either way. */
                    if (rc != DTL_ERR_TRUNCATED)
                        dtl_walk_report_error(w, si, record_in_sec, rc, 1);
                    break;
                }

                rc = dtl_record_parse(&tlv, a, &rec);
                if (rc != DTL_OK) {
                    dtl_walk_report_error(w, si, record_in_sec, rc, 0);
                    record_in_sec++;
                    continue;
                }

                ev.section_type = sec->type;
                ev.codec_id = sec->codec_id;
                ev.section_index = si;
                ev.record_in_sec = record_in_sec;
                ev.record_index = record_index;
                ev.rec = &rec;

                rc = w->on_record(&ev, w->user);
                if (rc != DTL_OK)
                    return rc;

                record_in_sec++;
                record_index++;
            }
        }

        /* Release this section's transient event payloads before moving on. */
        dtl_event_pool_release();
    }
    return DTL_OK;
}

dtl_err dtl_walk_absorb(const char *path, size_t max_file, dtl_arena *a,
                        const dtl_walk *w)
{
    FILE *f;
    long sz;
    size_t n;
    uint8_t *buf;

    if (path == NULL || a == NULL || w == NULL || w->on_record == NULL)
        return DTL_ERR_INVAL;

    f = fopen(path, "rb");
    if (f == NULL)
        return DTL_ERR_IO;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return DTL_ERR_IO; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return DTL_ERR_IO; }
    if ((unsigned long)sz > max_file) { fclose(f); return DTL_ERR_RANGE; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return DTL_ERR_IO; }

    n = (size_t)sz;
    buf = dtl_arena_alloc(a, n ? n : 1);
    if (buf == NULL) {
        fclose(f);
        return DTL_ERR_OOM;
    }
    if (n != 0 && fread(buf, 1, n, f) != n) {
        fclose(f);
        return DTL_ERR_IO;
    }
    fclose(f);

    return dtl_walk_memory(buf, n, a, w);
}

dtl_err dtl_walk_file(const char *path, size_t max_file, const dtl_walk *w)
{
    dtl_arena a;
    dtl_err rc;

    if (w == NULL || w->on_record == NULL)
        return DTL_ERR_INVAL;

    dtl_arena_init(&a, 256 * 1024);
    rc = dtl_walk_absorb(path, max_file, &a, w);
    dtl_arena_free(&a);
    return rc;
}
