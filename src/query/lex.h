#ifndef DTL_QUERY_LEX_H
#define DTL_QUERY_LEX_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * query/lex -- tokenizer for the filter DSL.
 *
 * Operates over a NUL-terminated query string, never reading past the NUL.
 * Invalid characters and unterminated strings are reported as DTL_ERR_BADQUERY.
 * For IDENT tokens, (s, n) point at the identifier bytes inside the source. For
 * STR tokens, (s, n) point at the RAW bytes between the quotes (escapes not yet
 * decoded); the parser decodes them into the arena.
 */

typedef enum dtl_token_kind {
    DTL_TOK_END = 0,
    DTL_TOK_NUM,
    DTL_TOK_STR,
    DTL_TOK_IDENT,
    DTL_TOK_AND,     /* && */
    DTL_TOK_OR,      /* || */
    DTL_TOK_EQ,      /* == */
    DTL_TOK_NE,      /* != */
    DTL_TOK_LT,      /* <  */
    DTL_TOK_LE,      /* <= */
    DTL_TOK_GT,      /* >  */
    DTL_TOK_GE,      /* >= */
    DTL_TOK_NOT,     /* !  */
    DTL_TOK_LPAREN,  /* (  */
    DTL_TOK_RPAREN,  /* )  */
    DTL_TOK_DOT      /* .  */
} dtl_token_kind;

typedef struct dtl_token {
    dtl_token_kind kind;
    int64_t        num; /* DTL_TOK_NUM */
    const char    *s;   /* DTL_TOK_STR / DTL_TOK_IDENT: bytes in the source */
    size_t         n;   /* length of s */
} dtl_token;

typedef struct dtl_lexer {
    const char *src;
    size_t      pos;
} dtl_lexer;

void dtl_lex_init(dtl_lexer *lx, const char *src);

/* Produce the next token. Returns DTL_OK (kind DTL_TOK_END at input end) or
 * DTL_ERR_BADQUERY. */
dtl_err dtl_lex_next(dtl_lexer *lx, dtl_token *out);

#endif /* DTL_QUERY_LEX_H */
