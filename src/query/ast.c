#include "query/ast.h"

#include <string.h>

static dtl_ast *dtl_ast_new(dtl_arena *a, dtl_ast_kind kind)
{
    dtl_ast *node = dtl_arena_alloc(a, sizeof *node);
    if (node == NULL)
        return NULL;
    node->kind = kind;
    node->op = DTL_CMP_EQ;
    node->left = NULL;
    node->right = NULL;
    node->ival = 0;
    node->s1 = NULL;
    node->n1 = 0;
    node->s2 = NULL;
    node->n2 = 0;
    return node;
}

/* Copy n bytes into a fresh, NUL-terminated arena buffer. */
static char *dtl_ast_dup(dtl_arena *a, const char *s, size_t n)
{
    char *buf = dtl_arena_alloc(a, n + 1);
    if (buf == NULL)
        return NULL;
    if (n != 0)
        memcpy(buf, s, n);
    buf[n] = '\0';
    return buf;
}

dtl_ast *dtl_ast_binary(dtl_arena *a, dtl_ast_kind kind,
                        dtl_ast *left, dtl_ast *right)
{
    dtl_ast *node = dtl_ast_new(a, kind);
    if (node == NULL)
        return NULL;
    node->left = left;
    node->right = right;
    return node;
}

dtl_ast *dtl_ast_cmp(dtl_arena *a, dtl_cmp_op op,
                     dtl_ast *left, dtl_ast *right)
{
    dtl_ast *node = dtl_ast_new(a, DTL_AST_CMP);
    if (node == NULL)
        return NULL;
    node->op = op;
    node->left = left;
    node->right = right;
    return node;
}

dtl_ast *dtl_ast_not(dtl_arena *a, dtl_ast *child)
{
    dtl_ast *node = dtl_ast_new(a, DTL_AST_NOT);
    if (node == NULL)
        return NULL;
    node->left = child;
    return node;
}

dtl_ast *dtl_ast_field(dtl_arena *a, const char *s1, size_t n1,
                       const char *s2, size_t n2)
{
    dtl_ast *node = dtl_ast_new(a, DTL_AST_FIELD);
    if (node == NULL)
        return NULL;

    node->s1 = dtl_ast_dup(a, s1, n1);
    if (node->s1 == NULL)
        return NULL;
    node->n1 = n1;

    if (s2 != NULL) {
        node->s2 = dtl_ast_dup(a, s2, n2);
        if (node->s2 == NULL)
            return NULL;
        node->n2 = n2;
    }
    return node;
}

dtl_ast *dtl_ast_int(dtl_arena *a, int64_t v)
{
    dtl_ast *node = dtl_ast_new(a, DTL_AST_INT);
    if (node == NULL)
        return NULL;
    node->ival = v;
    return node;
}

dtl_ast *dtl_ast_str(dtl_arena *a, const char *s, size_t n)
{
    dtl_ast *node = dtl_ast_new(a, DTL_AST_STR);
    if (node == NULL)
        return NULL;
    node->s1 = s;
    node->n1 = n;
    return node;
}
