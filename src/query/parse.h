#ifndef DTL_QUERY_PARSE_H
#define DTL_QUERY_PARSE_H

#include "core/arena.h"
#include "core/err.h"
#include "query/ast.h"

/* Maximum recursion depth accepted; deeper nesting is DTL_ERR_BADQUERY. */
#define DTL_QUERY_MAX_DEPTH 64

/*
 * dtl_parse -- lex and parse a whole query into an AST allocated from a.
 * Returns DTL_OK with *out_root set, or DTL_ERR_BADQUERY on any lex/parse error
 * (invalid token, syntax error, trailing input, over-deep nesting), or
 * DTL_ERR_OOM. Never recurses past DTL_QUERY_MAX_DEPTH, so malformed deeply
 * nested input cannot overflow the stack.
 */
dtl_err dtl_parse(const char *text, dtl_arena *a, dtl_ast **out_root);

#endif /* DTL_QUERY_PARSE_H */
