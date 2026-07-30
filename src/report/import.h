#ifndef DTL_REPORT_IMPORT_H
#define DTL_REPORT_IMPORT_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * report/import -- the inverse of report/export: parse a CSV record stream
 * back into a DTL container.
 *
 * The accepted layout is exactly what `dtl export <file> csv` emits: one
 * header row ("index,tag,f0..f5") followed by one row per record, the tag
 * column holding the printable type name and the f-columns holding the
 * type-specific tail. Quoted fields with doubled quotes are handled; hex
 * columns decode back into binary payloads. All records land in a single
 * STORE section (import is a data-ingestion path, not a byte-preserving
 * round-trip; use report/diff to verify record-level equivalence).
 */

/*
 * dtl_import_csv_file -- parse the CSV file at in_path (size-capped at
 * max_file bytes) and write the constructed container to out_path. Sets
 * *out_records (when non-NULL) to the number of records imported. Returns
 * DTL_OK on success, DTL_ERR_BADRECORD on malformed rows, or an I/O error.
 */
dtl_err dtl_import_csv_file(const char *in_path, const char *out_path,
                            size_t max_file, size_t *out_records);

/*
 * dtl_import_csv_memory -- parse CSV text held in memory and emit the
 * constructed container into arena a (out_bytes/out_len point into a).
 * Sets *out_records (when non-NULL) to the number of records imported.
 */
dtl_err dtl_import_csv_memory(const uint8_t *data, size_t len, dtl_arena *a,
                              uint8_t **out_bytes, size_t *out_len,
                              size_t *out_records);

#endif /* DTL_REPORT_IMPORT_H */
