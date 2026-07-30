#ifndef DTL_REPORT_VALIDATE_H
#define DTL_REPORT_VALIDATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "core/err.h"

/*
 * report/validate -- deep structural validation of a DTL container.
 *
 * Beyond what dtl_container_parse checks (header CRC, table bounds), the
 * validator decodes every section with its declared codec, verifies the
 * decompressed length matches raw_len exactly, walks the TLV stream to a
 * clean end, parses every record, and applies per-type semantic checks
 * (severity/percentage ranges, payload consistency, non-empty keys).
 *
 * Every finding is reported as an issue with a severity; the summary returns
 * nonzero when any error-severity issue exists.
 */

typedef enum dtl_validate_severity {
    DTL_VALIDATE_INFO = 0,
    DTL_VALIDATE_WARNING = 1,
    DTL_VALIDATE_ERROR = 2
} dtl_validate_severity;

typedef struct dtl_issue {
    dtl_validate_severity severity;
    uint16_t              section_index;
    size_t                record_in_sec;
    char                  message[96];
} dtl_issue;

typedef struct dtl_validate_report {
    dtl_issue *issues;        /* arena-allocated array                       */
    size_t     issue_count;
    size_t     issue_cap;
    size_t     records_checked;
    size_t     sections_checked;
    size_t     error_count;
    size_t     warning_count;
    struct dtl_arena *a;
} dtl_validate_report;

/*
 * dtl_validate_file -- validate the container at path (size-capped at
 * max_file bytes), storing issues in report (arena-backed; caller frees the
 * arena). Returns DTL_OK when validation ran to completion, regardless of
 * findings; inspect report->error_count for the verdict.
 */
dtl_err dtl_validate_file(const char *path, size_t max_file,
                          struct dtl_arena *a,
                          dtl_validate_report *report);

/*
 * dtl_validate_memory -- like dtl_validate_file, but validates a container
 * already held in memory. The arena a backs both the report and the walk's
 * decoded records, so it must outlive use of the report.
 */
dtl_err dtl_validate_memory(const uint8_t *data, size_t len,
                            struct dtl_arena *a,
                            dtl_validate_report *report);

/* dtl_validate_print -- list issues and print the summary line. */
void dtl_validate_print(const dtl_validate_report *report, FILE *out);

#endif /* DTL_REPORT_VALIDATE_H */
