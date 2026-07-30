#ifndef DTL_REPORT_JIMPORT_H
#define DTL_REPORT_JIMPORT_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * report/jimport -- the inverse of JSON export: parse the JSON record array
 * produced by `dtl export <file> json` back into a DTL container.
 *
 * The accepted document is a single JSON array of record objects. Each
 * object must carry "tag" (numeric) and may carry "type" (ignored on
 * import; the tag is authoritative) plus the type-specific fields the JSON
 * exporter emits. Strings use standard JSON escapes; hex fields decode back
 * into binary payloads. All records land in a single STORE section.
 */

/*
 * dtl_import_json_memory -- parse JSON text held in memory and emit the
 * constructed container into arena a (out_bytes/out_len point into a).
 * Sets *out_records (when non-NULL) to the number of records imported.
 * Returns DTL_ERR_BADRECORD on malformed JSON or schema violations.
 */
dtl_err dtl_import_json_memory(const uint8_t *data, size_t len, dtl_arena *a,
                               uint8_t **out_bytes, size_t *out_len,
                               size_t *out_records);

/*
 * dtl_import_json_file -- file wrapper around dtl_import_json_memory
 * (input size-capped at max_file bytes; container written to out_path).
 */
dtl_err dtl_import_json_file(const char *in_path, const char *out_path,
                             size_t max_file, size_t *out_records);

#endif /* DTL_REPORT_JIMPORT_H */
