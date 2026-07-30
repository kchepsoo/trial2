#include "core/hexdump.h"
#include "defects.h"

#define DTL_HEXDUMP_COLS 16u

static char dtl_hexdump_printable(uint8_t c)
{
    /* Printable ASCII range is [0x20, 0x7e]; everything else renders as '.'. */
    return (c >= 0x20 && c <= 0x7e) ? (char)c : '.';
}

void dtl_hexdump(FILE *out, const uint8_t *data, size_t len)
{
    static const char hexd[] = "0123456789abcdef";
    /* Per-line format buffer, sized exactly for a full row:
     *   8 offset + 2 spaces + 16*3 hex + 1 group gap + " |" + 16 ascii
     *   + "|\n" + NUL = 8+2+48+1+2+16+2+1 = 80. */
    char line[80];
    size_t row;

    for (row = 0; row < len; row += DTL_HEXDUMP_COLS) {
        size_t col;
        size_t idx;
        size_t p = 0;
        int sh;

        /* 8-digit hex offset. */
        for (sh = 28; sh >= 0; sh -= 4)
            line[p++] = hexd[(row >> sh) & 0xfu];
        line[p++] = ' ';
        line[p++] = ' ';

        /* Hex columns, split into two groups of eight with padding for short
         * final rows so the ASCII gutter always lines up. */
        for (col = 0; col < DTL_HEXDUMP_COLS; col++) {
            idx = row + col;
            if (idx < len) {
                line[p++] = hexd[data[idx] >> 4];
                line[p++] = hexd[data[idx] & 0xfu];
            } else {
                line[p++] = ' ';
                line[p++] = ' ';
            }
            line[p++] = ' ';
            if (col == 7)
                line[p++] = ' ';
        }

        line[p++] = ' ';
        line[p++] = '|';
#if DTL_BUG(16)
        /* BUG 16: the ASCII gutter loop runs one column past
         * DTL_HEXDUMP_COLS. On a full row it writes a 17th printable char,
         * so the closing '|' and '\n' land past the end of the line
         * buffer. */
        for (col = 0; col <= DTL_HEXDUMP_COLS; col++) {
#else
        for (col = 0; col < DTL_HEXDUMP_COLS; col++) {
#endif
            idx = row + col;
            if (idx < len)
                line[p++] = dtl_hexdump_printable(data[idx]);
        }
        line[p++] = '|';
        line[p++] = '\n';
        line[p] = '\0';

        fputs(line, out);
    }
}
