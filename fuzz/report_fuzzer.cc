// report_fuzzer -- exercises the report/import pipeline end to end.
//
// The fuzz input is interpreted three ways:
//   1. as CSV text for the CSV importer (dtl_import_csv_memory);
//   2. as JSON text for the JSON importer (dtl_import_json_memory);
//   3. as a raw serialized container (it may be one, via dictionary-guided
//      mutation of the seed corpus).
// Every container produced by (1) or (2) -- and the raw input itself in (3) --
// is then walked in memory (codec decode -> TLV framing -> typed record
// parse), exported record-by-record in both CSV and JSON to in-memory
// streams, and run through the deep validator. This is the same machinery
// behind `dtl stats|export|validate|timeline|topk`, driven without touching
// the filesystem.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" {
#include "core/arena.h"
#include "report/export.h"
#include "report/import.h"
#include "report/jimport.h"
#include "report/validate.h"
#include "report/walk.h"
}

namespace {

// Per-walk state: two in-memory export streams, one per format, so the
// export formatters run over every record the walk decodes.
struct Pipeline {
    FILE *csv;
    FILE *json;
    char *csv_buf;
    char *json_buf;
    size_t csv_len;
    size_t json_len;
    size_t records;
};

dtl_err OnRecord(const dtl_walk_event *ev, void *user) {
    Pipeline *p = static_cast<Pipeline *>(user);
    if (p->csv != nullptr)
        dtl_export_record(p->csv, DTL_EXPORT_CSV, ev->rec, p->records);
    if (p->json != nullptr)
        dtl_export_record(p->json, DTL_EXPORT_JSON, ev->rec, p->records);
    p->records++;
    return DTL_OK;
}

// Walk + validate a container held in memory. The caller guarantees bytes
// stays valid for the whole call; the walk and the validator finish within
// it and retain nothing past return.
void ExerciseContainer(const uint8_t *bytes, size_t len) {
    if (bytes == nullptr || len == 0)
        return;

    dtl_arena arena;
    dtl_arena_init(&arena, 64 * 1024);

    Pipeline p;
    p.csv_buf = nullptr;
    p.json_buf = nullptr;
    p.csv_len = 0;
    p.json_len = 0;
    p.records = 0;
    p.csv = open_memstream(&p.csv_buf, &p.csv_len);
    p.json = open_memstream(&p.json_buf, &p.json_len);

    dtl_walk w;
    w.on_record = OnRecord;
    w.on_error = nullptr;
    w.user = &p;
    w.max_decode = 0;
    dtl_walk_memory(bytes, len, &arena, &w);

    if (p.csv != nullptr)
        fclose(p.csv);
    if (p.json != nullptr)
        fclose(p.json);
    free(p.csv_buf);
    free(p.json_buf);

    dtl_validate_report rep;
    dtl_validate_memory(bytes, len, &arena, &rep);

    dtl_arena_free(&arena);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == nullptr || size == 0)
        return 0;

    // Path 1: the input as CSV import text.
    {
        dtl_arena arena;
        dtl_arena_init(&arena, 64 * 1024);
        uint8_t *out = nullptr;
        size_t out_len = 0;
        size_t records = 0;
        if (dtl_import_csv_memory(data, size, &arena, &out, &out_len,
                                  &records) == DTL_OK)
            ExerciseContainer(out, out_len);
        dtl_arena_free(&arena);
    }

    // Path 2: the input as JSON import text.
    {
        dtl_arena arena;
        dtl_arena_init(&arena, 64 * 1024);
        uint8_t *out = nullptr;
        size_t out_len = 0;
        size_t records = 0;
        if (dtl_import_json_memory(data, size, &arena, &out, &out_len,
                                   &records) == DTL_OK)
            ExerciseContainer(out, out_len);
        dtl_arena_free(&arena);
    }

    // Path 3: the input as a serialized container.
    ExerciseContainer(data, size);

    return 0;
}
