#include "report/jimport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec/registry.h"
#include "records/record.h"
#include "writer/writer.h"

/* ---- minimal JSON DOM ------------------------------------------------------
 * Arena-allocated node tree. Only what the exporter emits: objects, arrays,
 * strings, numbers, booleans, null. Numbers are kept as text and converted by
 * the field accessors so integer fields never lose precision through double.
 */

typedef enum dtl_json_kind {
    DTL_JSON_NULL = 0,
    DTL_JSON_BOOL,
    DTL_JSON_NUM,
    DTL_JSON_STR,
    DTL_JSON_ARR,
    DTL_JSON_OBJ
} dtl_json_kind;

typedef struct dtl_json_pair {
    char                *key;
    struct dtl_json_node *val;
} dtl_json_pair;

typedef struct dtl_json_node {
    dtl_json_kind kind;
    union {
        int    boolean;
        char  *num;   /* textual */
        char  *str;   /* unescaped */
        struct {
            struct dtl_json_node **items;
            size_t                 count;
        } arr;
        struct {
            dtl_json_pair *pairs;
            size_t         count;
        } obj;
    } u;
} dtl_json_node;

typedef struct dtl_json_parser {
    const uint8_t *p;
    const uint8_t *end;
    dtl_arena     *a;
    int            depth;
} dtl_json_parser;

#define DTL_JSON_MAX_DEPTH 64

static void dtl_json_skip_ws(dtl_json_parser *ps)
{
    while (ps->p < ps->end) {
        uint8_t c = *ps->p;
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            break;
        ps->p++;
    }
}

static int dtl_json_expect(dtl_json_parser *ps, uint8_t c)
{
    dtl_json_skip_ws(ps);
    if (ps->p >= ps->end || *ps->p != c)
        return -1;
    ps->p++;
    return 0;
}

static char *dtl_json_parse_string(dtl_json_parser *ps)
{
    /* entry: cursor on the opening quote */
    size_t cap = 32, n = 0;
    char *buf = dtl_arena_alloc(ps->a, cap);

    if (buf == NULL)
        return NULL;
    ps->p++; /* opening quote */

    for (;;) {
        uint8_t c;
        if (ps->p >= ps->end)
            return NULL;
        c = *ps->p++;
        if (c == '"')
            break;
        if (c == '\\') {
            if (ps->p >= ps->end)
                return NULL;
            c = *ps->p++;
            switch (c) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case '/': c = '/';  break;
            case '\\': c = '\\'; break;
            case '"': c = '"';  break;
            case 'u': {
                /* only the BMP escapes the exporter emits (control chars) */
                unsigned v = 0;
                int i;
                for (i = 0; i < 4; i++) {
                    uint8_t h;
                    if (ps->p >= ps->end)
                        return NULL;
                    h = *ps->p++;
                    v <<= 4;
                    if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
                    else return NULL;
                }
                if (v > 0x7F)
                    return NULL; /* exporter never emits these */
                c = (uint8_t)v;
                break;
            }
            default:
                return NULL;
            }
        }
        if (n + 1 >= cap) {
            size_t new_cap = cap * 2;
            char *grown = dtl_arena_alloc(ps->a, new_cap);
            if (grown == NULL)
                return NULL;
            memcpy(grown, buf, n);
            buf = grown;
            cap = new_cap;
        }
        buf[n++] = (char)c;
    }
    buf[n] = '\0';
    return buf;
}

static dtl_json_node *dtl_json_parse_value(dtl_json_parser *ps);

static dtl_json_node *dtl_json_new(dtl_json_parser *ps, dtl_json_kind kind)
{
    dtl_json_node *nd = dtl_arena_alloc(ps->a, sizeof(*nd));
    if (nd == NULL)
        return NULL;
    memset(nd, 0, sizeof(*nd));
    nd->kind = kind;
    return nd;
}

static dtl_json_node *dtl_json_parse_array(dtl_json_parser *ps)
{
    dtl_json_node *nd = dtl_json_new(ps, DTL_JSON_ARR);
    size_t cap = 8;
    dtl_json_node **items = dtl_arena_alloc(ps->a, cap * sizeof(*items));

    if (nd == NULL || items == NULL)
        return NULL;
    ps->p++; /* '[' */
    dtl_json_skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ']') {
        ps->p++;
        nd->u.arr.items = items;
        return nd;
    }
    for (;;) {
        dtl_json_node *val = dtl_json_parse_value(ps);
        if (val == NULL)
            return NULL;
        if (nd->u.arr.count == cap) {
            size_t new_cap = cap * 2;
            dtl_json_node **grown =
                dtl_arena_alloc(ps->a, new_cap * sizeof(*grown));
            if (grown == NULL)
                return NULL;
            memcpy(grown, items, nd->u.arr.count * sizeof(*grown));
            items = grown;
            cap = new_cap;
        }
        items[nd->u.arr.count++] = val;

        dtl_json_skip_ws(ps);
        if (ps->p >= ps->end)
            return NULL;
        if (*ps->p == ',') {
            ps->p++;
            continue;
        }
        if (*ps->p == ']') {
            ps->p++;
            break;
        }
        return NULL;
    }
    nd->u.arr.items = items;
    return nd;
}

static dtl_json_node *dtl_json_parse_object(dtl_json_parser *ps)
{
    dtl_json_node *nd = dtl_json_new(ps, DTL_JSON_OBJ);
    size_t cap = 8;
    dtl_json_pair *pairs = dtl_arena_alloc(ps->a, cap * sizeof(*pairs));

    if (nd == NULL || pairs == NULL)
        return NULL;
    ps->p++; /* '{' */
    dtl_json_skip_ws(ps);
    if (ps->p < ps->end && *ps->p == '}') {
        ps->p++;
        nd->u.obj.pairs = pairs;
        return nd;
    }
    for (;;) {
        char *key;
        dtl_json_node *val;

        dtl_json_skip_ws(ps);
        if (ps->p >= ps->end || *ps->p != '"')
            return NULL;
        key = dtl_json_parse_string(ps);
        if (key == NULL)
            return NULL;
        if (dtl_json_expect(ps, ':') != 0)
            return NULL;
        val = dtl_json_parse_value(ps);
        if (val == NULL)
            return NULL;

        if (nd->u.obj.count == cap) {
            size_t new_cap = cap * 2;
            dtl_json_pair *grown =
                dtl_arena_alloc(ps->a, new_cap * sizeof(*grown));
            if (grown == NULL)
                return NULL;
            memcpy(grown, pairs, nd->u.obj.count * sizeof(*grown));
            pairs = grown;
            cap = new_cap;
        }
        pairs[nd->u.obj.count].key = key;
        pairs[nd->u.obj.count].val = val;
        nd->u.obj.count++;

        dtl_json_skip_ws(ps);
        if (ps->p >= ps->end)
            return NULL;
        if (*ps->p == ',') {
            ps->p++;
            continue;
        }
        if (*ps->p == '}') {
            ps->p++;
            break;
        }
        return NULL;
    }
    nd->u.obj.pairs = pairs;
    return nd;
}

static dtl_json_node *dtl_json_parse_value(dtl_json_parser *ps)
{
    dtl_json_node *nd;

    if (++ps->depth > DTL_JSON_MAX_DEPTH)
        return NULL;
    dtl_json_skip_ws(ps);
    if (ps->p >= ps->end) {
        ps->depth--;
        return NULL;
    }

    switch (*ps->p) {
    case '{':
        nd = dtl_json_parse_object(ps);
        break;
    case '[':
        nd = dtl_json_parse_array(ps);
        break;
    case '"': {
        char *s = dtl_json_parse_string(ps);
        if (s == NULL) {
            ps->depth--;
            return NULL;
        }
        nd = dtl_json_new(ps, DTL_JSON_STR);
        if (nd != NULL)
            nd->u.str = s;
        break;
    }
    case 't':
        if ((size_t)(ps->end - ps->p) < 4 || memcmp(ps->p, "true", 4) != 0) {
            ps->depth--;
            return NULL;
        }
        ps->p += 4;
        nd = dtl_json_new(ps, DTL_JSON_BOOL);
        if (nd != NULL)
            nd->u.boolean = 1;
        break;
    case 'f':
        if ((size_t)(ps->end - ps->p) < 5 || memcmp(ps->p, "false", 5) != 0) {
            ps->depth--;
            return NULL;
        }
        ps->p += 5;
        nd = dtl_json_new(ps, DTL_JSON_BOOL);
        break;
    case 'n':
        if ((size_t)(ps->end - ps->p) < 4 || memcmp(ps->p, "null", 4) != 0) {
            ps->depth--;
            return NULL;
        }
        ps->p += 4;
        nd = dtl_json_new(ps, DTL_JSON_NULL);
        break;
    default: {
        /* number: [-]digits[.digits][eE[+-]digits] */
        const uint8_t *start = ps->p;
        size_t n;
        char *txt;
        if (*ps->p == '-')
            ps->p++;
        if (ps->p >= ps->end ||
            (*ps->p < '0' || *ps->p > '9')) {
            ps->depth--;
            return NULL;
        }
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
            ps->p++;
        if (ps->p < ps->end && *ps->p == '.') {
            ps->p++;
            while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
                ps->p++;
        }
        if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
            ps->p++;
            if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-'))
                ps->p++;
            while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
                ps->p++;
        }
        n = (size_t)(ps->p - start);
        txt = dtl_arena_alloc(ps->a, n + 1);
        if (txt == NULL) {
            ps->depth--;
            return NULL;
        }
        memcpy(txt, start, n);
        txt[n] = '\0';
        nd = dtl_json_new(ps, DTL_JSON_NUM);
        if (nd != NULL)
            nd->u.num = txt;
        break;
    }
    }
    ps->depth--;
    return nd;
}

/* ---- object field accessors -------------------------------------------------- */

static const dtl_json_node *dtl_json_get(const dtl_json_node *obj,
                                         const char *key)
{
    size_t i;
    if (obj == NULL || obj->kind != DTL_JSON_OBJ)
        return NULL;
    for (i = 0; i < obj->u.obj.count; i++) {
        if (strcmp(obj->u.obj.pairs[i].key, key) == 0)
            return obj->u.obj.pairs[i].val;
    }
    return NULL;
}

static int dtl_json_u32(const dtl_json_node *obj, const char *key,
                        uint32_t *out)
{
    const dtl_json_node *nd = dtl_json_get(obj, key);
    char *end = NULL;
    unsigned long v;
    if (nd == NULL || nd->kind != DTL_JSON_NUM)
        return -1;
    v = strtoul(nd->u.num, &end, 10);
    if (end == nd->u.num || *end != '\0' || v > 0xFFFFFFFFul)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

static int dtl_json_i32(const dtl_json_node *obj, const char *key,
                        int32_t *out)
{
    const dtl_json_node *nd = dtl_json_get(obj, key);
    char *end = NULL;
    long v;
    if (nd == NULL || nd->kind != DTL_JSON_NUM)
        return -1;
    v = strtol(nd->u.num, &end, 10);
    if (end == nd->u.num || *end != '\0')
        return -1;
    *out = (int32_t)v;
    return 0;
}

static int dtl_json_bool(const dtl_json_node *obj, const char *key, int *out)
{
    const dtl_json_node *nd = dtl_json_get(obj, key);
    if (nd == NULL || nd->kind != DTL_JSON_BOOL)
        return -1;
    *out = nd->u.boolean;
    return 0;
}

static const char *dtl_json_str(const dtl_json_node *obj, const char *key)
{
    const dtl_json_node *nd = dtl_json_get(obj, key);
    if (nd == NULL || nd->kind != DTL_JSON_STR)
        return NULL;
    return nd->u.str;
}

static int dtl_json_hex(const char *hex, uint8_t *out, size_t out_cap,
                        size_t *out_len)
{
    size_t n = strlen(hex);
    size_t i;
    if (n % 2 != 0 || n / 2 > out_cap)
        return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = hex[2 * i], lo = hex[2 * i + 1];
        hi = hi >= '0' && hi <= '9' ? hi - '0'
           : hi >= 'a' && hi <= 'f' ? hi - 'a' + 10
           : hi >= 'A' && hi <= 'F' ? hi - 'A' + 10 : -1;
        lo = lo >= '0' && lo <= '9' ? lo - '0'
           : lo >= 'a' && lo <= 'f' ? lo - 'a' + 10
           : lo >= 'A' && lo <= 'F' ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

/* ---- record object -> dtl_record ----------------------------------------------- */

static dtl_err dtl_jimport_record(dtl_arena *a, const dtl_json_node *obj,
                                  dtl_record *rec)
{
    uint32_t u0, u1, u2, u3, u4;
    int32_t s0, s1, s2;

    memset(rec, 0, sizeof(*rec));
    if (dtl_json_u32(obj, "tag", &u0) != 0 || u0 > 0xFF)
        return DTL_ERR_BADRECORD;
    rec->tag = (uint8_t)u0;

#define DTL_JU(dst, key)                                                      \
    do {                                                                      \
        if (dtl_json_u32(obj, key, &(dst)) != 0)                              \
            return DTL_ERR_BADRECORD;                                         \
    } while (0)
#define DTL_JI(dst, key)                                                      \
    do {                                                                      \
        if (dtl_json_i32(obj, key, &(dst)) != 0)                              \
            return DTL_ERR_BADRECORD;                                         \
    } while (0)

    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        DTL_JU(u0, "uptime_s");
        DTL_JU(u1, "seq");
        rec->u.heartbeat.uptime_s = u0;
        rec->u.heartbeat.seq = u1;
        break;
    case DTL_REC_SENSOR: {
        const dtl_json_node *arr = dtl_json_get(obj, "samples");
        float *samples;
        size_t i;
        uint8_t scount;
        DTL_JU(u0, "sensor_id");
        if (u0 > 0xFFFF || arr == NULL || arr->kind != DTL_JSON_ARR ||
            arr->u.arr.count > 0xFFFF)
            return DTL_ERR_BADRECORD;
        /* The record stores the sample count in a byte; size the buffer to
         * what the record will report so the wire form and the array agree. */
        scount = (uint8_t)arr->u.arr.count;
        samples = dtl_arena_alloc(a, (scount ? scount : 1) * sizeof(float));
        if (samples == NULL)
            return DTL_ERR_OOM;
        for (i = 0; i < arr->u.arr.count; i++) {
            const dtl_json_node *it = arr->u.arr.items[i];
            char *end = NULL;
            if (it->kind != DTL_JSON_NUM)
                return DTL_ERR_BADRECORD;
            samples[i] = strtof(it->u.num, &end);
            if (end == it->u.num)
                return DTL_ERR_BADRECORD;
        }
        rec->u.sensor.sensor_id = (uint16_t)u0;
        rec->u.sensor.count = scount;
        rec->u.sensor.samples = arr->u.arr.count ? samples : NULL;
        break;
    }
    case DTL_REC_EVENT: {
        const char *hex = dtl_json_str(obj, "payload_hex");
        size_t n = 0;
        uint8_t *payload;
        DTL_JU(u0, "code");
        if (u0 > 0xFFFF || hex == NULL)
            return DTL_ERR_BADRECORD;
        payload = dtl_arena_alloc(a, strlen(hex) / 2 + 1);
        if (payload == NULL)
            return DTL_ERR_OOM;
        if (dtl_json_hex(hex, payload, strlen(hex) / 2, &n) != 0 ||
            n > 0xFFFF)
            return DTL_ERR_BADRECORD;
        rec->u.event.code = (uint16_t)u0;
        rec->u.event.payload_len = (uint16_t)n;
        rec->u.event.payload = n ? payload : NULL;
        break;
    }
    case DTL_REC_DIAG: {
        const char *hex = dtl_json_str(obj, "blob_hex");
        int redacted = 0;
        size_t n = 0;
        uint8_t *blob;
        DTL_JU(u0, "subsystem");
        if (dtl_json_bool(obj, "redacted", &redacted) != 0)
            return DTL_ERR_BADRECORD;
        if (redacted)
            hex = ""; /* redacted exports carry no payload */
        if (u0 > 0xFFFF || hex == NULL)
            return DTL_ERR_BADRECORD;
        blob = dtl_arena_alloc(a, strlen(hex) / 2 + 1);
        if (blob == NULL)
            return DTL_ERR_OOM;
        if (dtl_json_hex(hex, blob, strlen(hex) / 2, &n) != 0 || n > 0xFFFF)
            return DTL_ERR_BADRECORD;
        rec->u.diag.subsystem = (uint16_t)u0;
        rec->u.diag.blob_len = (uint16_t)n;
        rec->u.diag.blob = n ? blob : NULL;
        rec->u.diag.redacted = (uint8_t)redacted;
        break;
    }
    case DTL_REC_GEO:
        DTL_JI(s0, "lat_e7");
        DTL_JI(s1, "lon_e7");
        DTL_JI(s2, "alt_mm");
        rec->u.geo.lat_e7 = s0;
        rec->u.geo.lon_e7 = s1;
        rec->u.geo.alt_mm = s2;
        break;
    case DTL_REC_BATTERY:
        DTL_JU(u0, "pct");
        DTL_JI(s0, "temp_c_e1");
        DTL_JU(u1, "cycles");
        if (u0 > 255 || s0 < -32768 || s0 > 32767)
            return DTL_ERR_BADRECORD;
        rec->u.battery.pct = (uint8_t)u0;
        rec->u.battery.temp_c_e1 = (int16_t)s0;
        rec->u.battery.cycles = u1;
        break;
    case DTL_REC_NET:
        DTL_JU(u0, "iface_id");
        DTL_JU(u1, "rx_bytes");
        DTL_JU(u2, "tx_bytes");
        DTL_JU(u3, "rx_pkts");
        DTL_JU(u4, "tx_pkts");
        if (u0 > 255)
            return DTL_ERR_BADRECORD;
        rec->u.net.iface_id = (uint8_t)u0;
        rec->u.net.rx_bytes = u1;
        rec->u.net.tx_bytes = u2;
        rec->u.net.rx_pkts = u3;
        rec->u.net.tx_pkts = u4;
        break;
    case DTL_REC_LOG: {
        const char *msg = dtl_json_str(obj, "msg");
        size_t n;
        char *copy;
        DTL_JU(u0, "severity");
        if (u0 > 255 || msg == NULL)
            return DTL_ERR_BADRECORD;
        n = strlen(msg);
        if (n > 0xFFFF)
            return DTL_ERR_BADRECORD;
        copy = dtl_arena_alloc(a, n + 1);
        if (copy == NULL)
            return DTL_ERR_OOM;
        memcpy(copy, msg, n + 1);
        rec->u.log.severity = (uint8_t)u0;
        rec->u.log.msg = copy;
        rec->u.log.msg_len = (uint16_t)n;
        break;
    }
    case DTL_REC_CONFIG: {
        const dtl_json_node *pairs_obj = dtl_json_get(obj, "pairs");
        dtl_config_pair *pairs;
        uint8_t pcount;
        size_t i;
        if (pairs_obj == NULL || pairs_obj->kind != DTL_JSON_OBJ ||
            pairs_obj->u.obj.count > 0xFFFF)
            return DTL_ERR_BADRECORD;
        /* The record carries the pair count in a byte; allocate to match so
         * the array and the reported count use the same width. */
        pcount = (uint8_t)pairs_obj->u.obj.count;
        pairs = dtl_arena_alloc(a, (pcount ? pcount : 1) * sizeof(*pairs));
        if (pairs == NULL)
            return DTL_ERR_OOM;
        for (i = 0; i < pairs_obj->u.obj.count; i++) {
            const dtl_json_node *v = pairs_obj->u.obj.pairs[i].val;
            const char *key = pairs_obj->u.obj.pairs[i].key;
            char *kcopy, *vcopy;
            if (v->kind != DTL_JSON_STR)
                return DTL_ERR_BADRECORD;
            kcopy = dtl_arena_alloc(a, strlen(key) + 1);
            vcopy = dtl_arena_alloc(a, strlen(v->u.str) + 1);
            if (kcopy == NULL || vcopy == NULL)
                return DTL_ERR_OOM;
            memcpy(kcopy, key, strlen(key) + 1);
            memcpy(vcopy, v->u.str, strlen(v->u.str) + 1);
            pairs[i].key = kcopy;
            pairs[i].value = vcopy;
        }
        rec->u.config.pair_count = pcount;
        rec->u.config.pairs = pcount ? pairs : NULL;
        break;
    }
    case DTL_REC_KEYREF: {
        const char *label = dtl_json_str(obj, "label");
        int redacted = 0;
        size_t n;
        char *copy;
        DTL_JU(u0, "slot_id");
        if (dtl_json_bool(obj, "redacted", &redacted) != 0)
            return DTL_ERR_BADRECORD;
        if (u0 > 255)
            return DTL_ERR_BADRECORD;
        if (label == NULL || redacted)
            label = "";
        n = strlen(label);
        if (n > 255)
            return DTL_ERR_BADRECORD;
        copy = dtl_arena_alloc(a, n + 1);
        if (copy == NULL)
            return DTL_ERR_OOM;
        memcpy(copy, label, n + 1);
        rec->u.keyref.slot_id = (uint8_t)u0;
        rec->u.keyref.redacted = (uint8_t)redacted;
        rec->u.keyref.label = copy;
        rec->u.keyref.label_len = (uint8_t)n;
        break;
    }
    case DTL_REC_FIRMWARE: {
        const char *ver = dtl_json_str(obj, "version");
        const char *hex = dtl_json_str(obj, "hash_hex");
        size_t n = 0;
        unsigned mj, mi, pa;
        if (ver == NULL || hex == NULL ||
            sscanf(ver, "%u.%u.%u", &mj, &mi, &pa) != 3 ||
            mj > 0xFFFF || mi > 0xFFFF || pa > 0xFFFF)
            return DTL_ERR_BADRECORD;
        if (dtl_json_hex(hex, rec->u.firmware.hash, 8, &n) != 0 || n != 8)
            return DTL_ERR_BADRECORD;
        rec->u.firmware.major = (uint16_t)mj;
        rec->u.firmware.minor = (uint16_t)mi;
        rec->u.firmware.patch = (uint16_t)pa;
        break;
    }
    default:
        return DTL_ERR_BADRECORD;
    }
#undef DTL_JU
#undef DTL_JI
    return DTL_OK;
}

/* ---- top level -------------------------------------------------------------------- */

dtl_err dtl_import_json_memory(const uint8_t *data, size_t len, dtl_arena *a,
                               uint8_t **out_bytes, size_t *out_len,
                               size_t *out_records)
{
    dtl_json_parser ps;
    dtl_json_node *root;
    dtl_writer w;
    dtl_err rc;
    size_t i;
    int section_open = 0;

    if (data == NULL || a == NULL || out_bytes == NULL || out_len == NULL)
        return DTL_ERR_INVAL;

    ps.p = data;
    ps.end = data + len;
    ps.a = a;
    ps.depth = 0;

    dtl_json_skip_ws(&ps);
    if (ps.p >= ps.end || *ps.p != '[')
        return DTL_ERR_BADRECORD;
    root = dtl_json_parse_array(&ps);
    if (root == NULL)
        return DTL_ERR_BADRECORD;
    dtl_json_skip_ws(&ps);
    if (ps.p != ps.end)
        return DTL_ERR_BADRECORD; /* trailing garbage */

    dtl_writer_init(&w, a);
    for (i = 0; i < root->u.arr.count; i++) {
        dtl_record rec;

        rc = dtl_jimport_record(a, root->u.arr.items[i], &rec);
        if (rc != DTL_OK)
            return rc;

        if (!section_open) {
            if (dtl_writer_begin_section(&w, 1, DTL_CODEC_STORE) < 0)
                return DTL_ERR_OOM;
            section_open = 1;
        }
        rc = dtl_writer_add_record(&w, &rec);
        if (rc != DTL_OK)
            return rc;
    }
    if (section_open) {
        rc = dtl_writer_end_section(&w);
        if (rc != DTL_OK)
            return rc;
    }
    rc = dtl_writer_finish(&w, out_bytes, out_len);
    if (rc != DTL_OK)
        return rc;

    if (out_records != NULL)
        *out_records = root->u.arr.count;
    return DTL_OK;
}

dtl_err dtl_import_json_file(const char *in_path, const char *out_path,
                             size_t max_file, size_t *out_records)
{
    FILE *in;
    FILE *out = NULL;
    dtl_arena a;
    dtl_err rc = DTL_OK;
    long sz;
    size_t n;
    uint8_t *data;
    uint8_t *bytes = NULL;
    size_t out_len = 0;

    if (in_path == NULL || out_path == NULL)
        return DTL_ERR_INVAL;

    in = fopen(in_path, "rb");
    if (in == NULL)
        return DTL_ERR_IO;
    if (fseek(in, 0, SEEK_END) != 0) { fclose(in); return DTL_ERR_IO; }
    sz = ftell(in);
    if (sz < 0 || (unsigned long)sz > max_file) {
        fclose(in);
        return sz < 0 ? DTL_ERR_IO : DTL_ERR_RANGE;
    }
    if (fseek(in, 0, SEEK_SET) != 0) { fclose(in); return DTL_ERR_IO; }

    n = (size_t)sz;
    dtl_arena_init(&a, 256 * 1024);
    data = dtl_arena_alloc(&a, n ? n : 1);
    if (data == NULL) {
        fclose(in);
        dtl_arena_free(&a);
        return DTL_ERR_OOM;
    }
    if (n != 0 && fread(data, 1, n, in) != n) {
        fclose(in);
        dtl_arena_free(&a);
        return DTL_ERR_IO;
    }
    fclose(in);

    rc = dtl_import_json_memory(data, n, &a, &bytes, &out_len, out_records);
    if (rc != DTL_OK)
        goto done;

    out = fopen(out_path, "wb");
    if (out == NULL) {
        rc = DTL_ERR_IO;
        goto done;
    }
    if (out_len != 0 && fwrite(bytes, 1, out_len, out) != out_len)
        rc = DTL_ERR_IO;

done:
    if (out != NULL)
        fclose(out);
    dtl_arena_free(&a);
    return rc;
}
