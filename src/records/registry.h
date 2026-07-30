#ifndef DTL_RECORDS_REGISTRY_H
#define DTL_RECORDS_REGISTRY_H

#include "core/arena.h"
#include "core/err.h"
#include "format/tlv.h"
#include "records/record.h"

/*
 * records/registry -- dispatch a TLV item to the parser for its tag.
 *
 * dtl_record_parse reads the payload strictly from tlv->val[0..tlv->len) via the
 * per-type parser and, on success, fills *out (including out->tag). An unknown
 * tag is reported as DTL_ERR_BADRECORD; any per-type failure (wrong length, over-
 * read) is propagated. The arena is passed through for records that need it.
 */
dtl_err dtl_record_parse(const dtl_tlv *tlv, dtl_arena *a, dtl_record *out);

#endif /* DTL_RECORDS_REGISTRY_H */
