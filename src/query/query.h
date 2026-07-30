#ifndef DTL_QUERY_QUERY_H
#define DTL_QUERY_QUERY_H

#include "core/arena.h"
#include "core/err.h"
#include "query/ast.h"
#include "records/record.h"

/*
 * query/query -- top-level filter compile + match.
 *
 * A dtl_query is a compiled filter, allocated entirely within the arena passed
 * to dtl_query_compile; it stays valid for that arena's lifetime.
 */
typedef struct dtl_query {
    const dtl_ast *root;
} dtl_query;

/*
 * dtl_query_compile -- lex and parse text into a compiled query in the arena.
 * Returns DTL_OK with *out set, or DTL_ERR_BADQUERY / DTL_ERR_OOM.
 */
dtl_err dtl_query_compile(const char *text, dtl_arena *a, dtl_query **out);

/* dtl_query_match -- 1 if rec matches the query, 0 otherwise. */
int dtl_query_match(const dtl_query *q, const dtl_record *rec);

#endif /* DTL_QUERY_QUERY_H */
