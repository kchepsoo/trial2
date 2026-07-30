#include "format/render.h"

size_t dtl_render_u32(char *out, size_t cap, uint32_t v)
{
    char tmp[10]; /* UINT32_MAX = 4294967295: 10 digits */
    size_t n = 0;
    size_t i = 0;

    do {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    } while (v != 0);

    while (n > 0 && i + 1 < cap)
        out[i++] = tmp[--n];
    if (cap > 0)
        out[i] = '\0';
    return i;
}
