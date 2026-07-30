#!/bin/bash -eu
# ClusterFuzzLite build for telemetry-forge.
#
# Compiles the production sources once into a static archive with the
# platform-provided compiler and flags, then links each fuzz harness into its
# own executable in $OUT. Fully offline: nothing is downloaded, no package
# manager runs, and the only generated file (dtl_seed.h) is produced by a host
# tool built from sources in this tree.

cd "$SRC"

WORK_DIR="${WORK:-$SRC/.fuzz-build}"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/obj" "$WORK_DIR/gen"

# ---------------------------------------------------------------------------
# Build-time device-key header. tools/make_key cannot link the crypto library
# (build_key.c includes the header this step generates), so it is compiled
# directly from the KDF/hash sources with the platform compiler.
# ---------------------------------------------------------------------------
"$CC" $CFLAGS -I"$SRC/src" \
    "$SRC/tools/make_key.c" \
    "$SRC/src/crypto/kdf.c" \
    "$SRC/src/crypto/hash.c" \
    "$SRC/src/core/endian.c" \
    -o "$WORK_DIR/make_key"
"$WORK_DIR/make_key" "${DTL_SEED:-telemetry-forge-dev-seed-v1}" \
    "$WORK_DIR/gen/dtl_seed.h"

# ---------------------------------------------------------------------------
# Production sources (everything under src/ except the smoke tests and the
# CLI front-end main).
# ---------------------------------------------------------------------------
SOURCES="
src/core/err.c
src/core/endian.c
src/core/buf.c
src/core/arena.c
src/core/hexdump.c
src/format/crc.c
src/format/container.c
src/format/tlv.c
src/format/render.c
src/codec/store.c
src/codec/rle.c
src/codec/varint.c
src/codec/lz77.c
src/codec/dict.c
src/codec/delta.c
src/codec/base32.c
src/codec/registry.c
src/records/heartbeat.c
src/records/geo.c
src/records/battery.c
src/records/firmware.c
src/records/net.c
src/records/sensor.c
src/records/event.c
src/records/log.c
src/records/config.c
src/records/keyref.c
src/records/diag.c
src/records/registry.c
src/crypto/hash.c
src/crypto/kdf.c
src/crypto/keystore.c
src/crypto/redact.c
src/crypto/build_key.c
src/query/lex.c
src/query/ast.c
src/query/parse.c
src/query/eval.c
src/query/query.c
src/writer/writer.c
src/report/walk.c
src/report/stats.c
src/report/index.c
src/report/export.c
src/report/validate.c
src/report/diff.c
src/report/merge.c
src/report/split.c
src/report/repack.c
src/report/select.c
src/report/import.c
src/report/jimport.c
src/report/timeline.c
src/report/topk.c
src/report/dedup.c
src/report/sample.c
src/report/sign.c
"

for f in $SOURCES; do
    obj="$WORK_DIR/obj/$(echo "$f" | tr '/.' '__').o"
    "$CC" $CFLAGS -I"$SRC/src" -I"$WORK_DIR/gen" -c "$SRC/$f" -o "$obj"
done

ar rcs "$WORK_DIR/libdtl.a" "$WORK_DIR"/obj/*.o

# ---------------------------------------------------------------------------
# One executable per harness, linked with the platform fuzzing engine.
# ---------------------------------------------------------------------------
for harness in container_fuzzer query_fuzzer codec_fuzzer protocol_fuzzer report_fuzzer; do
    "$CXX" $CXXFLAGS -I"$SRC/src" -I"$WORK_DIR/gen" \
        "$SRC/fuzz/${harness}.cc" \
        "$WORK_DIR/libdtl.a" \
        $LIB_FUZZING_ENGINE \
        -o "$OUT/${harness}"
done
