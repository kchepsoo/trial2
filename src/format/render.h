#ifndef DTL_FORMAT_RENDER_H
#define DTL_FORMAT_RENDER_H

#include <stddef.h>
#include <stdint.h>

/*
 * format/render -- fixed-width integer rendering.
 *
 * dtl_render_u32 writes the decimal representation of v into out (at most
 * cap-1 chars plus NUL, truncated if cap is too small) and returns the number
 * of characters written (excluding NUL). out may be NULL only when cap is 0.
 */
size_t dtl_render_u32(char *out, size_t cap, uint32_t v);

#endif /* DTL_FORMAT_RENDER_H */
