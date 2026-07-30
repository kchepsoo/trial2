#ifndef DTL_REPORT_TOPK_H
#define DTL_REPORT_TOPK_H

#include <stddef.h>
#include <stdio.h>

#include "core/err.h"

/*
 * report/topk -- rank records by a numeric field and print the top N.
 *
 * The field is named with the same dotted syntax the query DSL uses
 * ("battery.pct", "net.rx_bytes", ...). Only records carrying the field
 * participate. Ranking is stable: equal values keep wire order.
 */

/* dtl_topk_field_exists -- nonzero when name is a rankable field. */
int dtl_topk_field_exists(const char *name);

/* dtl_topk_list_fields -- print the rankable field names. */
void dtl_topk_list_fields(FILE *out);

/*
 * dtl_topk_file -- print the top n records of the container at path
 * (size-capped at max_file bytes) ranked descending by field. n == 0 prints
 * every matching record. Returns DTL_ERR_INVAL for an unknown field.
 */
dtl_err dtl_topk_file(const char *path, size_t max_file, const char *field,
                      size_t n, FILE *out);

#endif /* DTL_REPORT_TOPK_H */
