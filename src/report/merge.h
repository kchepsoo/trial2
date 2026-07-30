#ifndef DTL_REPORT_MERGE_H
#define DTL_REPORT_MERGE_H

#include <stddef.h>

#include "core/err.h"

/*
 * report/merge -- combine several DTL containers into one.
 *
 * Every input container is walked; its records are regrouped by tag and
 * written to a single output container with one section per tag present
 * (sections use the STORE codec so the merge is byte-deterministic for a
 * given input set). HMAC trailers are not carried over -- the merged
 * container is a new artifact; callers can re-sign it with dtl writer tools.
 */

/*
 * dtl_merge_files -- merge the container files paths[0..count) into the
 * output file out_path. Each input is size-capped at max_file bytes.
 * Returns DTL_OK on success, or the first read/parse/write error.
 */
dtl_err dtl_merge_files(const char **paths, size_t count, size_t max_file,
                        const char *out_path);

#endif /* DTL_REPORT_MERGE_H */
