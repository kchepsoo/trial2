# telemetry-forge

A strict C99 toolkit for the **DTL (Device Telemetry Log)** binary container
format: encoder, decoder, verifier, query engine, reporting tools, and a
command-line front end. DTL containers carry batches of typed telemetry
records (heartbeats, sensor samples, network counters, logs, diagnostics,
and more) between an embedded device and its analysis host.

## Supported platforms

* Linux and macOS, x86-64 and arm64.
* The project is **Clang-only**: the sanitizer configurations include
  MemorySanitizer, which has no GCC equivalent. Any recent Clang (>= 14)
  with CMake >= 3.20 and Ninja or Make works.
* No third-party dependencies. A clean checkout builds offline.

## The DTL container format

All multi-byte fields are little-endian.

```
header (12 bytes)
  magic         u32   0x014C5444  ("DTL\x01")
  version       u8    (currently 1)
  flags         u8    (bit0 = HMAC trailer present)
  section_count u16
  header_crc    u32   CRC-32 over the 8 preceding header bytes

section table (section_count x 16 bytes)
  type u16 | codec_id u8 | reserved u8 | raw_len u32 | comp_len u32 | offset u32

blob region       concatenated (possibly compressed) section payloads
hmac trailer      32 bytes, present when flags bit0 is set
```

Section payloads are sequences of TLV records (`tag u8, len u16, val[len]`).
Eleven record types are defined (tags `0x10`-`0x1A`): HEARTBEAT, SENSOR,
EVENT, DIAG, GEO, BATTERY, NET, LOG, CONFIG, KEYREF, FIRMWARE. Sections may
be compressed with one of the bundled codecs:

| id | codec  | notes                                  |
|----|--------|----------------------------------------|
| 0  | store  | identity, no compression               |
| 1  | RLE    | run-length pairs                       |
| 2  | varint | LEB128 integer streams                 |
| 3  | LZ77   | literal/match back-references          |
| 4  | dict   | dictionary token substitution          |
| 5  | delta  | delta-of-integers                      |
| 6  | base32 | RFC 4648 base32 text                   |

The HMAC trailer is a keyed ARX-sponge MAC (32 bytes) over everything but the
trailer itself. The device key is derived at build time from the `DTL_SEED`
build variable (KDF output); key material is never hardcoded in the source.

## Components

```
src/core      errors, endian helpers, buffer reader, bump-arena allocator,
              hexdump (the arena is ASan-aware: sub-allocations are poisoned)
src/format    CRC-32, container parse, TLV framing, integer rendering
src/codec     the seven codecs above + dispatch registry
src/records   the eleven typed record parsers + tag registry
src/crypto    keyed hash, KDF, keystore, record redaction, build-time key
src/query     filter DSL: lexer -> parser -> AST -> evaluator
src/writer    incremental container encoder with optional HMAC trailer
src/report    reporting/transformation tools built on a shared walk pipeline:
              stats, index, export (CSV/JSON), import (CSV + JSON), validate,
              diff, merge, split, repack, select, timeline, topk, dedup,
              sample, sign
src/cli       the dtl front end
tools/        gen_corpus (procedural DTL generator), make_key (seed header)
fuzz/         ClusterFuzzLite harnesses, seed corpora, dictionary
```

## Building

```sh
cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=clang
ninja -C build
```

One configure produces three configurations of every module side by side:

* `dtl`      - optimized (`-O2`), no sanitizer
* `dtl_asan` - AddressSanitizer + UndefinedBehaviorSanitizer
* `dtl_msan` - MemorySanitizer with origin tracking

`DTL_SEED` (CMake cache variable) selects the device key: changing it and
reconfiguring produces a build whose `verify` expects containers signed with
the new key.

## Tests

```sh
ctest --test-dir build --output-on-failure
```

Every module ships a smoke binary; `ctest` runs all of them in all three
configurations (27 tests). The report smoke is an end-to-end oracle: it
synthesizes containers with the writer and checks walk/stats/index/export/
validate/diff/merge/split/repack/select/import/sign against ground truth,
plus the timeline/topk/dedup/sample oracles, including CSV and JSON
export -> import round-trips verified record-for-record with `diff`.

## Using the tools

```sh
dtl decode <file>                 # parse and print every record (redacted)
dtl dump <file>                   # header + section table summary
dtl verify <file> [--key <hex>]   # check the HMAC trailer
dtl query <expr> <file>           # filter records with the query DSL
dtl stats <file>                  # aggregate statistics
dtl index <file>                  # per-tag posting counts
dtl export <file> <csv|json>      # serialize records
dtl import <csv> <out>            # rebuild a container from exported CSV
dtl import-json <json> <out>      # rebuild a container from exported JSON
dtl validate <file>               # deep structural + semantic checks
dtl diff <a> <b>                  # record-level comparison
dtl merge <out> <in> [<in> ...]   # combine containers (grouped per tag)
dtl split <file> <dir> [prefix]   # one output container per record tag
dtl repack <in> <out> <codec-id>  # transcode every section
dtl select <expr> <in> <out>      # extract matching records
dtl timeline <file>               # heartbeat sessions, gap/ordering anomalies
dtl topk <file> <field> <n>       # rank records by a numeric field
dtl dedup <in> <out>              # drop field-for-field duplicate records
dtl sample <in> <out> <n> <seed>  # deterministic reservoir sample
dtl sign <in> <out> --key <hex>   # attach an HMAC trailer
```

Query DSL examples: `type == LOG`, `battery.pct <= 20 && seq > 100`,
`(type == SENSOR && sensor_id == 3) || geo.lat > 0`.

## Fuzzing

The repository is ClusterFuzzLite-ready: `.clusterfuzzlite/build.sh` builds
five harnesses (`container_fuzzer`, `query_fuzzer`, `codec_fuzzer`,
`protocol_fuzzer`, `report_fuzzer`) into `$OUT` with the platform-provided
compiler flags and fuzzing engine. Each harness drives the same production
code paths the CLI uses (container parse -> codec decode -> TLV walk ->
record parse -> redaction, query compile/evaluate, codec round-trips, the
HMAC verify protocol, and -- in `report_fuzzer` -- the whole report/import
pipeline: CSV and JSON import, in-memory walk, both export formatters, and
the deep validator). Per-harness seed corpora live under `fuzz/corpus/`,
and `fuzz/dictionary.txt` carries the format and DSL tokens.

To fuzz locally with libFuzzer:

```sh
SRC=$PWD OUT=$PWD/out CC=clang CXX=clang++ \
CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" \
CXXFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" \
LIB_FUZZING_ENGINE="-fsanitize=address,fuzzer" \
bash .clusterfuzzlite/build.sh
./out/container_fuzzer fuzz/corpus/container_fuzzer -max_total_time=300
```

The build is fully offline and deterministic: nothing is downloaded, the
only generated file (`dtl_seed.h`) is produced by a host tool compiled from
in-tree sources.

## Limitations

* Container files are memory-mapped by value: inputs are capped at 16 MiB
  (`DTL_CLI_MAX_FILE`) and a section's decompressed size at 64 MiB
  (`DTL_SECTION_MAX_RAW`).
* The query evaluator resolves fields against single records; cross-record
  aggregation is `dtl stats` territory, not the DSL's.
* merge/split/repack/select/import/dedup/sample produce new unsigned
  artifacts; apply `dtl sign` afterwards when an HMAC trailer is required.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2024-2026 the telemetry-forge
authors.
