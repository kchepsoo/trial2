#ifndef DTL_REPORT_DEDUP_H
#define DTL_REPORT_DEDUP_H

#include <stddef.h>

#include "core/err.h"

/*
 * report/dedup -- remove duplicate records from a container.
 *
 * Two records are duplicates when they compare field-for-field identical
 * (the same comparator report/diff uses, ignoring redaction state). The
 * first occurrence in wire order is kept; later duplicates are dropped.
 * Section structure is preserved: each input section that contributes at
 * least one kept record yields one output section with the same type and
 * codec; fully-emptied sections disappear.
 */

/*
 * dtl_dedup_file -- rewrite the container at in_path to out_path with
 * duplicate records removed. Inputs are size-capped at max_file bytes. Sets
 * *out_dropped (when non-NULL) to the number of records removed.
 */
dtl_err dtl_dedup_file(const char *in_path, const char *out_path,
                       size_t max_file, size_t *out_dropped);

#endif /* DTL_REPORT_DEDUP_H */
