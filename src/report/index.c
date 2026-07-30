#include "report/index.h"

#include <string.h>

#include "report/walk.h"

static dtl_err dtl_index_append(dtl_index *idx, const dtl_walk_event *ev)
{
    dtl_index_chunk *ch = idx->tail;
    dtl_index_entry *e;

    if (ch == NULL || ch->count == 256) {
        ch = dtl_arena_alloc(idx->a, sizeof(*ch));
        if (ch == NULL)
            return DTL_ERR_OOM;
        ch->count = 0;
        ch->next = NULL;
        if (idx->tail != NULL)
            idx->tail->next = ch;
        else
            idx->head = ch;
        idx->tail = ch;
    }

    e = &ch->entries[ch->count++];
    e->tag = ev->rec->tag;
    e->section_index = ev->section_index;
    e->record_in_sec = (uint32_t)ev->record_in_sec;
    e->record_index = (uint32_t)ev->record_index;
    idx->per_tag[e->tag]++;
    idx->total++;
    return DTL_OK;
}

static dtl_err dtl_index_on_record(const dtl_walk_event *ev, void *user)
{
    return dtl_index_append(user, ev);
}

dtl_err dtl_index_build(const char *path, size_t max_file, dtl_arena *a,
                        dtl_index *idx)
{
    dtl_walk w;

    if (idx == NULL || a == NULL)
        return DTL_ERR_INVAL;

    memset(idx, 0, sizeof(*idx));
    idx->a = a;

    w.on_record = dtl_index_on_record;
    w.on_error = NULL;
    w.user = idx;
    w.max_decode = 0;
    return dtl_walk_file(path, max_file, &w);
}

size_t dtl_index_foreach_tag(const dtl_index *idx, uint8_t tag,
                             void (*cb)(const dtl_index_entry *e, void *user),
                             void *user)
{
    const dtl_index_chunk *ch;
    size_t matched = 0;
    size_t i;

    for (ch = idx->head; ch != NULL; ch = ch->next) {
        for (i = 0; i < ch->count; i++) {
            const dtl_index_entry *e = &ch->entries[i];
            if (e->tag == tag) {
                matched++;
                if (cb != NULL)
                    cb(e, user);
            }
        }
    }
    return matched;
}

void dtl_index_print(const dtl_index *idx, FILE *out)
{
    int tag;

    fprintf(out, "indexed-records: %llu\n", (unsigned long long)idx->total);
    fprintf(out, "postings:\n");
    for (tag = 0; tag < 256; tag++) {
        if (idx->per_tag[tag])
            fprintf(out, "  %-10s %llu\n", dtl_walk_tag_name((uint8_t)tag),
                    (unsigned long long)idx->per_tag[tag]);
    }
}
