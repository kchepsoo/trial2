#ifndef DTL_REPORT_EXPORT_H
#define DTL_REPORT_EXPORT_H

#include <stddef.h>
#include <stdio.h>

#include "core/err.h"
#include "records/record.h"

/*
 * report/export -- serialize a container's records as CSV or JSON.
 *
 * CSV mode emits one header row and one row per record with a stable column
 * layout ("tag,index,..." plus a type-specific tail). JSON mode emits a
 * single JSON array of record objects; both are written to a caller-provided
 * FILE*. Strings are quoted/escaped so the output is machine-consumable.
 */

typedef enum dtl_export_format {
    DTL_EXPORT_CSV = 0,
    DTL_EXPORT_JSON = 1
} dtl_export_format;

/* dtl_export_record -- serialize one record; index is its global ordinal. */
void dtl_export_record(FILE *out, dtl_export_format fmt,
                       const dtl_record *rec, size_t index);

/*
 * dtl_export_file -- export every record of the container at path
 * (size-capped at max_file bytes) to out in the requested format.
 */
dtl_err dtl_export_file(const char *path, size_t max_file,
                        dtl_export_format fmt, FILE *out);

/* dtl_export_format_name -- parse "csv" / "json"; -1 when unrecognized. */
int dtl_export_parse_format(const char *name, dtl_export_format *out);

#endif /* DTL_REPORT_EXPORT_H */
