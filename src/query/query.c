#include "query/query.h"

#include "query/eval.h"
#include "query/parse.h"

dtl_err dtl_query_compile(const char *text, dtl_arena *a, dtl_query **out)
{
    dtl_ast *root;
    dtl_query *q;
    dtl_err rc;

    rc = dtl_parse(text, a, &root);
    if (rc != DTL_OK)
        return rc;

    q = dtl_arena_alloc(a, sizeof *q);
    if (q == NULL)
        return DTL_ERR_OOM;
    q->root = root;

    *out = q;
    return DTL_OK;
}

int dtl_query_match(const dtl_query *q, const dtl_record *rec)
{
    return dtl_query_eval(q->root, rec);
}
