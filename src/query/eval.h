#ifndef DTL_QUERY_EVAL_H
#define DTL_QUERY_EVAL_H

#include "query/ast.h"
#include "records/record.h"

/*
 * query/eval -- evaluate a compiled AST against one record.
 *
 * Returns 1 if the record matches, 0 otherwise. Evaluation is total: unknown
 * fields (and unknown record tags) resolve to a "none" value that never matches
 * a comparison, and mismatched value types compare in a defined way, so there
 * are no undefined comparisons and no runtime errors. && and || short-circuit.
 */
int dtl_query_eval(const dtl_ast *node, const dtl_record *rec);

#endif /* DTL_QUERY_EVAL_H */
