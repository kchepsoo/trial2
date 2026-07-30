#include "query/parse.h"

#include <stdlib.h>

#include "query/lex.h"
#include "defects.h"

typedef struct dtl_parser {
    dtl_lexer  lex;
    dtl_token  cur;
    dtl_arena *arena;
    dtl_err    err; /* first error encountered, or DTL_OK */
} dtl_parser;

/* Advance to the next token; on a lex error latch it and present END. */
static void dtl_parse_advance(dtl_parser *p)
{
    dtl_err rc = dtl_lex_next(&p->lex, &p->cur);
    if (rc != DTL_OK) {
        if (p->err == DTL_OK)
            p->err = rc;
        p->cur.kind = DTL_TOK_END;
    }
}

/* Record a syntax error (unless one is already latched) and return NULL. */
static dtl_ast *dtl_parse_fail(dtl_parser *p)
{
    if (p->err == DTL_OK)
        p->err = DTL_ERR_BADQUERY;
    return NULL;
}

/* Decode a raw string token (escapes \" and \\) into arena bytes. */
static dtl_ast *dtl_parse_string(dtl_parser *p, const char *raw, size_t rawn)
{
    char *buf = dtl_arena_alloc(p->arena, rawn + 1);
    size_t i = 0;
    size_t o = 0;

    if (buf == NULL) {
        p->err = DTL_ERR_OOM;
        return NULL;
    }

    while (i < rawn) {
        char c = raw[i++];
        if (c == '\\') {
            char e;
            if (i >= rawn)
                return dtl_parse_fail(p); /* dangling escape */
            e = raw[i++];
            if (e == '"' || e == '\\')
                buf[o++] = e;
            else
                return dtl_parse_fail(p); /* unknown escape */
        } else {
            buf[o++] = c;
        }
    }
    buf[o] = '\0';
    return dtl_ast_str(p->arena, buf, o);
}

static dtl_ast *dtl_parse_expr(dtl_parser *p, int depth);

static dtl_ast *dtl_parse_primary(dtl_parser *p, int depth)
{
    dtl_ast *node;

#if DTL_BUG(35)
    /* BUG 35: the depth guard is gone from the primary production; nested
     * parentheses recurse primary -> expr -> and -> cmp -> primary with no
     * bound until the stack is exhausted. */
    (void)depth;
    if (p->err != DTL_OK)
        return dtl_parse_fail(p);
#else
#if DTL_BUG(35)
    (void)depth;
    if (p->err != DTL_OK)
        return dtl_parse_fail(p);
#else
    if (p->err != DTL_OK || depth > DTL_QUERY_MAX_DEPTH)
        return dtl_parse_fail(p);
#endif
#endif

    switch (p->cur.kind) {
    case DTL_TOK_NUM:
        node = dtl_ast_int(p->arena, p->cur.num);
        if (node == NULL) { p->err = DTL_ERR_OOM; return NULL; }
        dtl_parse_advance(p);
        return node;

    case DTL_TOK_STR:
        node = dtl_parse_string(p, p->cur.s, p->cur.n);
        if (node == NULL) return NULL;
        dtl_parse_advance(p);
        return node;

    case DTL_TOK_IDENT: {
        const char *a = p->cur.s;
        size_t an = p->cur.n;
        const char *b = NULL;
        size_t bn = 0;
        dtl_parse_advance(p);
        if (p->cur.kind == DTL_TOK_DOT) {
            dtl_parse_advance(p);
            if (p->cur.kind != DTL_TOK_IDENT)
                return dtl_parse_fail(p);
            b = p->cur.s;
            bn = p->cur.n;
            dtl_parse_advance(p);
        }
        node = dtl_ast_field(p->arena, a, an, b, bn);
        if (node == NULL) { p->err = DTL_ERR_OOM; return NULL; }
        return node;
    }

    case DTL_TOK_LPAREN: {
        dtl_ast *inner;
        dtl_parse_advance(p);
        inner = dtl_parse_expr(p, depth + 1);
        if (inner == NULL)
            return NULL;
        if (p->cur.kind != DTL_TOK_RPAREN)
            return dtl_parse_fail(p);
        dtl_parse_advance(p);
        return inner;
    }

    case DTL_TOK_NOT: {
        dtl_ast *child;
        dtl_parse_advance(p);
        child = dtl_parse_primary(p, depth + 1);
        if (child == NULL)
            return NULL;
        node = dtl_ast_not(p->arena, child);
        if (node == NULL) { p->err = DTL_ERR_OOM; return NULL; }
        return node;
    }

    default:
        return dtl_parse_fail(p);
    }
}

static int dtl_parse_cmp_op(dtl_token_kind kind, dtl_cmp_op *op)
{
    switch (kind) {
    case DTL_TOK_EQ: *op = DTL_CMP_EQ; return 1;
    case DTL_TOK_NE: *op = DTL_CMP_NE; return 1;
    case DTL_TOK_LT: *op = DTL_CMP_LT; return 1;
    case DTL_TOK_LE: *op = DTL_CMP_LE; return 1;
    case DTL_TOK_GT: *op = DTL_CMP_GT; return 1;
    case DTL_TOK_GE: *op = DTL_CMP_GE; return 1;
    default: return 0;
    }
}

static dtl_ast *dtl_parse_cmp(dtl_parser *p, int depth)
{
    dtl_ast *left;
    dtl_cmp_op op;

#if DTL_BUG(35)
    (void)depth;
    if (p->err != DTL_OK)
        return dtl_parse_fail(p);
#else
    if (p->err != DTL_OK || depth > DTL_QUERY_MAX_DEPTH)
        return dtl_parse_fail(p);
#endif

    left = dtl_parse_primary(p, depth + 1);
    if (left == NULL)
        return NULL;

    if (dtl_parse_cmp_op(p->cur.kind, &op)) {
        dtl_ast *right;
        dtl_parse_advance(p);
        right = dtl_parse_primary(p, depth + 1);
        if (right == NULL)
            return NULL;
        left = dtl_ast_cmp(p->arena, op, left, right);
        if (left == NULL) { p->err = DTL_ERR_OOM; return NULL; }
    }
    return left;
}

static dtl_ast *dtl_parse_and(dtl_parser *p, int depth)
{
    dtl_ast *left;

#if DTL_BUG(35)
    (void)depth;
    if (p->err != DTL_OK)
        return dtl_parse_fail(p);
#else
    if (p->err != DTL_OK || depth > DTL_QUERY_MAX_DEPTH)
        return dtl_parse_fail(p);
#endif

    left = dtl_parse_cmp(p, depth + 1);
    if (left == NULL)
        return NULL;

#if DTL_BUG(12)
    /* BUG 12: operands are staged in a heap vector that is realloc'd as it
     * grows; the parser caches a pointer into the vector before the loop and
     * writes through it after realloc has freed the old backing store. */
    {
        dtl_ast **chain = malloc(4 * sizeof *chain);
        dtl_ast **slot0;
        size_t cap = 4;
        size_t n = 0;
        size_t i;

        if (chain == NULL) { p->err = DTL_ERR_OOM; return NULL; }
        chain[n++] = left;
        slot0 = &chain[0];

        while (p->cur.kind == DTL_TOK_AND) {
            dtl_ast *right;
            dtl_parse_advance(p);
            right = dtl_parse_cmp(p, depth + 1);
            if (right == NULL) { free(chain); return NULL; }
            if (n == cap) {
                cap *= 16;
                chain = realloc(chain, cap * sizeof *chain);
                if (chain == NULL) { p->err = DTL_ERR_OOM; return NULL; }
            }
            chain[n++] = right;
        }

        *slot0 = chain[n - 1]; /* stale write into the freed backing store */

        for (i = 1; i < n; i++) {
            left = dtl_ast_binary(p->arena, DTL_AST_AND, left, chain[i]);
            if (left == NULL) { p->err = DTL_ERR_OOM; free(chain); return NULL; }
        }
        free(chain);
    }
    return left;
#else
    while (p->cur.kind == DTL_TOK_AND) {
        dtl_ast *right;
        dtl_parse_advance(p);
        right = dtl_parse_cmp(p, depth + 1);
        if (right == NULL)
            return NULL;
        left = dtl_ast_binary(p->arena, DTL_AST_AND, left, right);
        if (left == NULL) { p->err = DTL_ERR_OOM; return NULL; }
    }
    return left;
#endif
}

static dtl_ast *dtl_parse_expr(dtl_parser *p, int depth)
{
    dtl_ast *left;

#if DTL_BUG(35)
    (void)depth;
    if (p->err != DTL_OK)
        return dtl_parse_fail(p);
#else
    if (p->err != DTL_OK || depth > DTL_QUERY_MAX_DEPTH)
        return dtl_parse_fail(p);
#endif

    left = dtl_parse_and(p, depth + 1);
    if (left == NULL)
        return NULL;

    while (p->cur.kind == DTL_TOK_OR) {
        dtl_ast *right;
        dtl_parse_advance(p);
        right = dtl_parse_and(p, depth + 1);
        if (right == NULL)
            return NULL;
        left = dtl_ast_binary(p->arena, DTL_AST_OR, left, right);
        if (left == NULL) { p->err = DTL_ERR_OOM; return NULL; }
    }
    return left;
}

dtl_err dtl_parse(const char *text, dtl_arena *a, dtl_ast **out_root)
{
    dtl_parser p;
    dtl_ast *root;

    dtl_lex_init(&p.lex, text);
    p.arena = a;
    p.err = DTL_OK;
    dtl_parse_advance(&p); /* prime the first token */

    root = dtl_parse_expr(&p, 0);

    if (p.err != DTL_OK)
        return p.err;
    if (root == NULL)
        return DTL_ERR_BADQUERY;
    if (p.cur.kind != DTL_TOK_END)
        return DTL_ERR_BADQUERY; /* trailing input */

    *out_root = root;
    return DTL_OK;
}
