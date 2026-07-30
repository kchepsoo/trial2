#include "query/eval.h"

#include <string.h>

#include "defects.h"

/* A resolved value: an integer, a (bytes,len) string, or "none" (no value). */
typedef enum { DTL_VAL_NONE, DTL_VAL_INT, DTL_VAL_STR } dtl_val_kind;

typedef struct {
    dtl_val_kind kind;
    int64_t      i;
    const char  *s;
    size_t       n;
} dtl_value;

static dtl_value dtl_val_none(void)
{
    dtl_value v;
    v.kind = DTL_VAL_NONE;
    v.i = 0;
    v.s = NULL;
    v.n = 0;
    return v;
}

static dtl_value dtl_val_int(int64_t i)
{
    dtl_value v = dtl_val_none();
    v.kind = DTL_VAL_INT;
    v.i = i;
    return v;
}

static dtl_value dtl_val_str(const char *s, size_t n)
{
    dtl_value v = dtl_val_none();
    v.kind = DTL_VAL_STR;
    v.s = s;
    v.n = n;
    return v;
}

/* name (s,n) equals the NUL-terminated literal? (case-sensitive) */
static int dtl_name_eq(const char *s, size_t n, const char *lit)
{
    return strlen(lit) == n && memcmp(s, lit, n) == 0;
}

static char dtl_ascii_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

/* Case-insensitive name equality, used for record-type names only. */
static int dtl_name_ieq(const char *s, size_t n, const char *lit)
{
    size_t i;
    if (strlen(lit) != n)
        return 0;
    for (i = 0; i < n; i++)
        if (dtl_ascii_lower(s[i]) != dtl_ascii_lower(lit[i]))
            return 0;
    return 1;
}

/*
 * Map a record-type name to its tag. Type names are matched case-insensitively,
 * so both the value constant form ("type == HEARTBEAT") and the dotted-field
 * qualifier form ("battery.pct") resolve. Returns 1 and sets *tag on success.
 */
static int dtl_typename_tag(const char *s, size_t n, uint8_t *tag)
{
    static const struct { const char *name; uint8_t tag; } names[] = {
        { "HEARTBEAT", DTL_REC_HEARTBEAT },
        { "SENSOR",    DTL_REC_SENSOR },
        { "EVENT",     DTL_REC_EVENT },
        { "DIAG",      DTL_REC_DIAG },
        { "GEO",       DTL_REC_GEO },
        { "BATTERY",   DTL_REC_BATTERY },
        { "NET",       DTL_REC_NET },
        { "LOG",       DTL_REC_LOG },
        { "CONFIG",    DTL_REC_CONFIG },
        { "KEYREF",    DTL_REC_KEYREF },
        { "FIRMWARE",  DTL_REC_FIRMWARE }
    };
    size_t k;
    for (k = 0; k < sizeof names / sizeof names[0]; k++) {
        if (dtl_name_ieq(s, n, names[k].name)) {
            *tag = names[k].tag;
            return 1;
        }
    }
    return 0;
}

/* Resolve a bare field name against the current record's payload. */
static dtl_value dtl_field_value(const dtl_record *rec, const char *s, size_t n)
{
    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        if (dtl_name_eq(s, n, "seq"))    return dtl_val_int(rec->u.heartbeat.seq);
        if (dtl_name_eq(s, n, "uptime")) return dtl_val_int(rec->u.heartbeat.uptime_s);
        break;
    case DTL_REC_GEO:
        if (dtl_name_eq(s, n, "lat")) return dtl_val_int(rec->u.geo.lat_e7);
        if (dtl_name_eq(s, n, "lon")) return dtl_val_int(rec->u.geo.lon_e7);
        if (dtl_name_eq(s, n, "alt")) return dtl_val_int(rec->u.geo.alt_mm);
        break;
    case DTL_REC_BATTERY:
        if (dtl_name_eq(s, n, "pct"))    return dtl_val_int(rec->u.battery.pct);
        if (dtl_name_eq(s, n, "temp"))   return dtl_val_int(rec->u.battery.temp_c_e1);
        if (dtl_name_eq(s, n, "cycles")) return dtl_val_int((int64_t)rec->u.battery.cycles);
        break;
    case DTL_REC_NET:
        if (dtl_name_eq(s, n, "iface"))    return dtl_val_int(rec->u.net.iface_id);
        if (dtl_name_eq(s, n, "rx_bytes")) return dtl_val_int((int64_t)rec->u.net.rx_bytes);
        if (dtl_name_eq(s, n, "tx_bytes")) return dtl_val_int((int64_t)rec->u.net.tx_bytes);
        if (dtl_name_eq(s, n, "rx_pkts"))  return dtl_val_int((int64_t)rec->u.net.rx_pkts);
        if (dtl_name_eq(s, n, "tx_pkts"))  return dtl_val_int((int64_t)rec->u.net.tx_pkts);
        break;
    case DTL_REC_FIRMWARE:
        if (dtl_name_eq(s, n, "major")) return dtl_val_int(rec->u.firmware.major);
        if (dtl_name_eq(s, n, "minor")) return dtl_val_int(rec->u.firmware.minor);
        if (dtl_name_eq(s, n, "patch")) return dtl_val_int(rec->u.firmware.patch);
        break;
    case DTL_REC_SENSOR:
        if (dtl_name_eq(s, n, "id"))    return dtl_val_int(rec->u.sensor.sensor_id);
        if (dtl_name_eq(s, n, "count")) return dtl_val_int(rec->u.sensor.count);
        break;
    case DTL_REC_EVENT:
        if (dtl_name_eq(s, n, "code")) return dtl_val_int(rec->u.event.code);
        if (dtl_name_eq(s, n, "len"))  return dtl_val_int(rec->u.event.payload_len);
        break;
    case DTL_REC_LOG:
        if (dtl_name_eq(s, n, "severity")) return dtl_val_int(rec->u.log.severity);
        if (dtl_name_eq(s, n, "len"))      return dtl_val_int(rec->u.log.msg_len);
        if (dtl_name_eq(s, n, "msg"))
            return dtl_val_str(rec->u.log.msg, rec->u.log.msg_len);
        break;
    case DTL_REC_CONFIG: {
        /* The field name is looked up as a config key. */
        uint8_t i;
        for (i = 0; i < rec->u.config.pair_count; i++) {
            const char *key = rec->u.config.pairs[i].key;
            if (dtl_name_eq(s, n, key))
                return dtl_val_str(rec->u.config.pairs[i].value,
                                   strlen(rec->u.config.pairs[i].value));
        }
        break;
    }
    case DTL_REC_KEYREF:
        if (dtl_name_eq(s, n, "slot"))  return dtl_val_int(rec->u.keyref.slot_id);
        if (dtl_name_eq(s, n, "label"))
            return dtl_val_str(rec->u.keyref.label, rec->u.keyref.label_len);
        break;
    case DTL_REC_DIAG:
        if (dtl_name_eq(s, n, "subsystem")) return dtl_val_int(rec->u.diag.subsystem);
        if (dtl_name_eq(s, n, "len"))       return dtl_val_int(rec->u.diag.blob_len);
        break;
    default:
        break;
    }
    return dtl_val_none();
}

/* Resolve a FIELD node (possibly dotted) against a record. */
static dtl_value dtl_resolve(const dtl_ast *node, const dtl_record *rec)
{
    uint8_t tag;

    if (node->s2 == NULL) {
        /* bare ident: "type", a type-name constant, or a record field */
        if (dtl_name_eq(node->s1, node->n1, "type"))
            return dtl_val_int(rec->tag);
        if (dtl_typename_tag(node->s1, node->n1, &tag))
            return dtl_val_int(tag);
        return dtl_field_value(rec, node->s1, node->n1);
    }

    /* dotted: the qualifier must name this record's type. */
    if (!dtl_typename_tag(node->s1, node->n1, &tag))
        return dtl_val_none();
    if (rec->tag != tag)
        return dtl_val_none();
    return dtl_field_value(rec, node->s2, node->n2);
}

static int dtl_int_cmp(int64_t a, int64_t b, dtl_cmp_op op)
{
#if DTL_BUG(30)
    /* BUG 30: ordering comparisons are done on the unsigned bit pattern, so
     * a negative field value sorts above every non-negative literal and
     * range filters silently include/exclude the wrong records. */
    uint64_t ua = (uint64_t)a;
    uint64_t ub = (uint64_t)b;

    switch (op) {
    case DTL_CMP_EQ: return ua == ub;
    case DTL_CMP_NE: return ua != ub;
    case DTL_CMP_LT: return ua < ub;
    case DTL_CMP_LE: return ua <= ub;
    case DTL_CMP_GT: return ua > ub;
    case DTL_CMP_GE: return ua >= ub;
    }
    return 0;
#else
    switch (op) {
    case DTL_CMP_EQ: return a == b;
    case DTL_CMP_NE: return a != b;
    case DTL_CMP_LT: return a < b;
    case DTL_CMP_LE: return a <= b;
    case DTL_CMP_GT: return a > b;
    case DTL_CMP_GE: return a >= b;
    }
    return 0;
#endif
}

static int dtl_str_cmp(const dtl_value *a, const dtl_value *b, dtl_cmp_op op)
{
    size_t m = a->n < b->n ? a->n : b->n;
    int c = (m == 0) ? 0 : memcmp(a->s, b->s, m);
    if (c == 0)
        c = (a->n < b->n) ? -1 : (a->n > b->n ? 1 : 0);

    switch (op) {
    case DTL_CMP_EQ: return c == 0;
    case DTL_CMP_NE: return c != 0;
    case DTL_CMP_LT: return c < 0;
    case DTL_CMP_LE: return c <= 0;
    case DTL_CMP_GT: return c > 0;
    case DTL_CMP_GE: return c >= 0;
    }
    return 0;
}

/* Total comparison: none never matches; mismatched types are unequal. */
static int dtl_compare(const dtl_value *l, const dtl_value *r, dtl_cmp_op op)
{
    if (l->kind == DTL_VAL_NONE || r->kind == DTL_VAL_NONE)
        return 0;
    if (l->kind == DTL_VAL_INT && r->kind == DTL_VAL_INT)
        return dtl_int_cmp(l->i, r->i, op);
    if (l->kind == DTL_VAL_STR && r->kind == DTL_VAL_STR)
        return dtl_str_cmp(l, r, op);
    /* int vs string: comparable only for (in)equality, always unequal. */
    if (op == DTL_CMP_EQ) return 0;
    if (op == DTL_CMP_NE) return 1;
    return 0;
}

static dtl_value dtl_eval_value(const dtl_ast *node, const dtl_record *rec);

static int dtl_truthy(dtl_value v)
{
    switch (v.kind) {
    case DTL_VAL_INT:  return v.i != 0;
    case DTL_VAL_STR:  return v.n != 0;
    case DTL_VAL_NONE: return 0;
    }
    return 0;
}

static dtl_value dtl_eval_value(const dtl_ast *node, const dtl_record *rec)
{
    switch (node->kind) {
    case DTL_AST_INT:
        return dtl_val_int(node->ival);
    case DTL_AST_STR:
        return dtl_val_str(node->s1, node->n1);
    case DTL_AST_FIELD:
        return dtl_resolve(node, rec);
    case DTL_AST_NOT:
        return dtl_val_int(!dtl_truthy(dtl_eval_value(node->left, rec)));
    case DTL_AST_AND: {
        if (!dtl_truthy(dtl_eval_value(node->left, rec)))
            return dtl_val_int(0); /* short-circuit */
        return dtl_val_int(dtl_truthy(dtl_eval_value(node->right, rec)));
    }
    case DTL_AST_OR: {
        if (dtl_truthy(dtl_eval_value(node->left, rec)))
            return dtl_val_int(1); /* short-circuit */
        return dtl_val_int(dtl_truthy(dtl_eval_value(node->right, rec)));
    }
    case DTL_AST_CMP: {
        dtl_value l = dtl_eval_value(node->left, rec);
        dtl_value r = dtl_eval_value(node->right, rec);
        return dtl_val_int(dtl_compare(&l, &r, node->op));
    }
    }
    return dtl_val_none();
}

int dtl_query_eval(const dtl_ast *node, const dtl_record *rec)
{
    return dtl_truthy(dtl_eval_value(node, rec));
}
