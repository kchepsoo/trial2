#include "query/lex.h"


static int dtl_lex_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int dtl_lex_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int dtl_lex_is_ident_start(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int dtl_lex_is_ident(char c)
{
    return dtl_lex_is_ident_start(c) || dtl_lex_is_digit(c);
}

void dtl_lex_init(dtl_lexer *lx, const char *src)
{
    lx->src = src;
    lx->pos = 0;
}

/* Lex a (possibly negative) decimal integer starting at lx->pos. */
static dtl_err dtl_lex_number(dtl_lexer *lx, dtl_token *out)
{
    const char *s = lx->src;
    int negative = 0;
    int64_t val = 0;

    if (s[lx->pos] == '-') {
        negative = 1;
        lx->pos++;
    }
    if (!dtl_lex_is_digit(s[lx->pos]))
        return DTL_ERR_BADQUERY; /* a lone '-' */

    while (dtl_lex_is_digit(s[lx->pos])) {
        int d = s[lx->pos] - '0';
        /* Guard against int64 overflow before multiplying. */
        if (val > (INT64_MAX - d) / 10)
            return DTL_ERR_BADQUERY;
        val = val * 10 + d;
        lx->pos++;
    }

    out->kind = DTL_TOK_NUM;
    out->num = negative ? -val : val;
    return DTL_OK;
}

/* Lex a double-quoted string; lx->pos is at the opening quote. */
static dtl_err dtl_lex_string(dtl_lexer *lx, dtl_token *out)
{
    const char *s = lx->src;
    size_t start;

    lx->pos++; /* skip opening quote */
    start = lx->pos;

    for (;;) {
        char c = s[lx->pos];
        if (c == '\0')
            return DTL_ERR_BADQUERY; /* unterminated */
        if (c == '"') {
            out->kind = DTL_TOK_STR;
            out->s = s + start;
            out->n = lx->pos - start;
            lx->pos++; /* skip closing quote */
            return DTL_OK;
        }
        if (c == '\\') {
            lx->pos++;
            if (s[lx->pos] == '\0')
                return DTL_ERR_BADQUERY; /* backslash then end */
            lx->pos++; /* consume the escaped char */
            continue;
        }
        lx->pos++;
    }
}

dtl_err dtl_lex_next(dtl_lexer *lx, dtl_token *out)
{
    const char *s = lx->src;
    char c;

    while (dtl_lex_is_space(s[lx->pos]))
        lx->pos++;

    c = s[lx->pos];

    out->s = NULL;
    out->n = 0;
    out->num = 0;

    if (c == '\0') {
        out->kind = DTL_TOK_END;
        return DTL_OK;
    }

    /* number: a digit, or '-' immediately followed by a digit */
    if (dtl_lex_is_digit(c) ||
        (c == '-' && dtl_lex_is_digit(s[lx->pos + 1])))
        return dtl_lex_number(lx, out);

    if (dtl_lex_is_ident_start(c)) {
        size_t start = lx->pos;
        while (dtl_lex_is_ident(s[lx->pos]))
            lx->pos++;
        out->kind = DTL_TOK_IDENT;
        out->s = s + start;
        out->n = lx->pos - start;
        return DTL_OK;
    }

    if (c == '"')
        return dtl_lex_string(lx, out);

    /* Operators. For two-char operators the second char read is at pos+1,
     * which is in range because s[pos] is a non-NUL character. */
    switch (c) {
    case '&':
        if (s[lx->pos + 1] == '&') { lx->pos += 2; out->kind = DTL_TOK_AND; return DTL_OK; }
        return DTL_ERR_BADQUERY;
    case '|':
        if (s[lx->pos + 1] == '|') { lx->pos += 2; out->kind = DTL_TOK_OR; return DTL_OK; }
        return DTL_ERR_BADQUERY;
    case '=':
        if (s[lx->pos + 1] == '=') { lx->pos += 2; out->kind = DTL_TOK_EQ; return DTL_OK; }
        return DTL_ERR_BADQUERY;
    case '!':
        if (s[lx->pos + 1] == '=') { lx->pos += 2; out->kind = DTL_TOK_NE; return DTL_OK; }
        lx->pos++; out->kind = DTL_TOK_NOT; return DTL_OK;
    case '<':
        if (s[lx->pos + 1] == '=') { lx->pos += 2; out->kind = DTL_TOK_LE; return DTL_OK; }
        lx->pos++; out->kind = DTL_TOK_LT; return DTL_OK;
    case '>':
        if (s[lx->pos + 1] == '=') { lx->pos += 2; out->kind = DTL_TOK_GE; return DTL_OK; }
        lx->pos++; out->kind = DTL_TOK_GT; return DTL_OK;
    case '(':
        lx->pos++; out->kind = DTL_TOK_LPAREN; return DTL_OK;
    case ')':
        lx->pos++; out->kind = DTL_TOK_RPAREN; return DTL_OK;
    case '.':
        lx->pos++; out->kind = DTL_TOK_DOT; return DTL_OK;
    default:
        return DTL_ERR_BADQUERY; /* invalid character */
    }
}
