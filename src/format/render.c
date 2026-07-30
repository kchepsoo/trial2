#include "format/render.h"
#include "defects.h"

size_t dtl_render_u32(char *out, size_t cap, uint32_t v)
{
#if DTL_BUG(17)
    /* BUG 17: the digit scratch assumes a 32-bit value renders to at most 9
     * digits; UINT32_MAX renders to 10, so the most significant digit is
     * written one slot past the array. */
    char tmp[9];
#else
    char tmp[10]; /* UINT32_MAX = 4294967295: 10 digits */
#endif
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
