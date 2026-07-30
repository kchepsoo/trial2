#ifndef DTL_QUERY_AST_H
#define DTL_QUERY_AST_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"

/*
 * query/ast -- abstract syntax tree for a compiled filter.
 *
 * Every node, and every byte of identifier/string content it references, is
 * allocated from the arena passed to the constructors, so a compiled query is
 * self-contained and its lifetime is exactly the arena's. There is no raw
 * malloc/free anywhere in the query pipeline.
 */

typedef enum dtl_ast_kind {
    DTL_AST_OR,     /* left || right                         */
    DTL_AST_AND,    /* left && right                         */
    DTL_AST_CMP,    /* left <op> right                       */
    DTL_AST_NOT,    /* !left                                 */
    DTL_AST_FIELD,  /* field reference: s1 [ "." s2 ]        */
    DTL_AST_INT,    /* integer literal in ival               */
    DTL_AST_STR     /* string literal in (s1, n1), decoded   */
} dtl_ast_kind;

typedef enum dtl_cmp_op {
    DTL_CMP_EQ, DTL_CMP_NE, DTL_CMP_LT, DTL_CMP_LE, DTL_CMP_GT, DTL_CMP_GE
} dtl_cmp_op;

typedef struct dtl_ast {
    dtl_ast_kind    kind;
    dtl_cmp_op      op;    /* DTL_AST_CMP */
    struct dtl_ast *left;  /* OR/AND/CMP operand, or NOT operand */
    struct dtl_ast *right; /* OR/AND/CMP operand */
    int64_t         ival;  /* DTL_AST_INT */
    const char     *s1;    /* FIELD first ident, or STR bytes */
    size_t          n1;
    const char     *s2;    /* FIELD second ident (dotted), else NULL */
    size_t          n2;
} dtl_ast;

/* Constructors. Each returns NULL only if the arena is exhausted. */
dtl_ast *dtl_ast_binary(dtl_arena *a, dtl_ast_kind kind,
                        dtl_ast *left, dtl_ast *right);
dtl_ast *dtl_ast_cmp(dtl_arena *a, dtl_cmp_op op,
                     dtl_ast *left, dtl_ast *right);
dtl_ast *dtl_ast_not(dtl_arena *a, dtl_ast *child);
dtl_ast *dtl_ast_field(dtl_arena *a, const char *s1, size_t n1,
                       const char *s2, size_t n2);
dtl_ast *dtl_ast_int(dtl_arena *a, int64_t v);
/* s must already be arena-owned decoded bytes; stored without copying. */
dtl_ast *dtl_ast_str(dtl_arena *a, const char *s, size_t n);

#endif /* DTL_QUERY_AST_H */
