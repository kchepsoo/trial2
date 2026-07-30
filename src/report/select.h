#ifndef DTL_REPORT_SELECT_H
#define DTL_REPORT_SELECT_H

#include <stddef.h>

#include "core/err.h"

/*
 * report/select -- extract a filtered subset of a container's records into
 * a new container.
 *
 * The filter is a query expression compiled with the project's query engine
 * (the same language as `dtl query`). Matching records keep their original
 * relative order and are grouped per source section: each input section that
 * contributes at least one match yields one output section with the same
 * type id and codec. Non-matching sections disappear entirely.
 */

/*
 * dtl_select_file -- filter the container at in_path by expr, writing the
 * resulting container to out_path. Inputs are size-capped at max_file
 * bytes. Sets *out_kept (when non-NULL) to the number of records retained.
 * Returns DTL_OK on success, DTL_ERR_BADQUERY for an uncompilable filter.
 */
dtl_err dtl_select_file(const char *in_path, const char *out_path,
                        const char *expr, size_t max_file, size_t *out_kept);

#endif /* DTL_REPORT_SELECT_H */
