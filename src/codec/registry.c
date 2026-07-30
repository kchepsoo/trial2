#include "codec/registry.h"

#include <stdlib.h>
#include <string.h>

#include "defects.h"

#include "codec/base32.h"
#include "codec/delta.h"
#include "codec/dict.h"
#include "codec/lz77.h"
#include "codec/rle.h"
#include "codec/store.h"
#include "codec/varint.h"

/* Descriptors for all seven codecs (pass 1 + pass 2). */
static const dtl_codec dtl_codec_table[] = {
    { DTL_CODEC_STORE,  "store",  dtl_store_decode,  dtl_store_encode  },
    { DTL_CODEC_RLE,    "rle",    dtl_rle_decode,    dtl_rle_encode    },
    { DTL_CODEC_VARINT, "varint", dtl_varint_decode, dtl_varint_encode },
    { DTL_CODEC_LZ77,   "lz77",   dtl_lz77_decode,   dtl_lz77_encode   },
    { DTL_CODEC_DICT,   "dict",   dtl_dict_decode,   dtl_dict_encode   },
    { DTL_CODEC_DELTA,  "delta",  dtl_delta_decode,  dtl_delta_encode  },
    { DTL_CODEC_BASE32, "base32", dtl_base32_decode, dtl_base32_encode }
};

#define DTL_CODEC_COUNT (sizeof(dtl_codec_table) / sizeof(dtl_codec_table[0]))

const dtl_codec *dtl_codec_get(uint8_t codec_id)
{
#if DTL_BUG(23)
    /* BUG 23: the dispatch table is a tight private heap copy of exactly
     * DTL_CODEC_COUNT slots, and the boundary codec_id (BASE32, the last
     * valid id) is mis-indexed one slot past the end of the copy. */
    static dtl_codec *tab;
    size_t i;

    if (tab == NULL) {
        tab = malloc(sizeof(dtl_codec_table));
        if (tab != NULL)
            memcpy(tab, dtl_codec_table, sizeof(dtl_codec_table));
    }
    if (tab == NULL)
        return NULL;

    for (i = 0; i < DTL_CODEC_COUNT; i++) {
        if (tab[i].id == codec_id)
            return &tab[codec_id == DTL_CODEC_BASE32 ? i + 1 : i];
    }
    return NULL;
#else
    size_t i;

    for (i = 0; i < DTL_CODEC_COUNT; i++) {
        if (dtl_codec_table[i].id == codec_id)
            return &dtl_codec_table[i];
    }
    return NULL;
#endif
}
