#ifndef DTL_REPORT_DIFF_H
#define DTL_REPORT_DIFF_H

#include <stddef.h>
#include <stdio.h>

#include "core/arena.h"
#include "core/err.h"
#include "records/record.h"

/*
 * report/diff -- record-level comparison of two DTL containers.
 *
 * Both containers are walked; their record streams are compared pairwise in
 * wire order, field by field. Differences are printed as human-readable
 * lines ("record 7: tag LOG != CONFIG", "record 3: battery.pct 15 != 20").
 * A length mismatch reports the shorter stream's exhaustion and counts the
 * tail as additions/removals.
 *
 * dtl_diff_files returns the number of differing records (plus tail
 * records), so it doubles as an equality oracle for merge/split round-trips.
 */

typedef struct dtl_diff_options {
    int ignore_redaction; /* treat redacted and cleared fields as equal      */
    size_t max_report;    /* stop printing after this many diffs (0 = all)   */
} dtl_diff_options;

/*
 * dtl_diff_files -- compare the containers at path_a and path_b (each
 * size-capped at max_file bytes), printing differences to out. Sets
 * *out_diffs (when non-NULL) to the total number of differing records.
 * Returns DTL_OK when both containers were readable, or the first I/O or
 * parse error encountered.
 */
dtl_err dtl_diff_files(const char *path_a, const char *path_b,
                       size_t max_file, const dtl_diff_options *opts,
                       FILE *out, size_t *out_diffs);

/*
 * dtl_diff_records_equal -- field-for-field comparison of two parsed
 * records (the same comparator the file diff uses). Returns nonzero when
 * the records are identical. With ignore_redaction, redacted vs cleared
 * payloads compare equal.
 */
int dtl_diff_records_equal(const dtl_record *ra, const dtl_record *rb,
                           int ignore_redaction);

#endif /* DTL_REPORT_DIFF_H */
