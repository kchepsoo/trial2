#ifndef DTL_REPORT_SPLIT_H
#define DTL_REPORT_SPLIT_H

#include <stddef.h>
#include <stdio.h>

#include "core/err.h"

/*
 * report/split -- the inverse of merge: break one DTL container into
 * per-tag output containers.
 *
 * The input is walked once; for every record tag present, an output file
 * "<out_dir>/<prefix>_<TAG>.dtl" is written holding exactly that tag's
 * records, in their original relative order, in a single STORE section.
 */

/*
 * dtl_split_file -- split the container at path (size-capped at max_file
 * bytes) into per-tag files under out_dir with the given filename prefix.
 * Prints one line per written file to out (may be NULL). Returns DTL_OK on
 * success, or the first read/parse/write error.
 */
dtl_err dtl_split_file(const char *path, size_t max_file,
                       const char *out_dir, const char *prefix, FILE *out);

#endif /* DTL_REPORT_SPLIT_H */
