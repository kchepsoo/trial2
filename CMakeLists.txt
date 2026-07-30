cmake_minimum_required(VERSION 3.20)

project(telemetry-forge C)

# ---------------------------------------------------------------------------
# Language: strict C99, no compiler extensions.
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Compiler gate: MemorySanitizer is Clang-only, and the whole corpus is built
# and validated with clang-18. Refuse to configure with anything else so we
# never silently produce an un-sanitizable tree.
# ---------------------------------------------------------------------------
if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR
        "telemetry-forge must be built with Clang (expected clang-18); "
        "detected C compiler is '${CMAKE_C_COMPILER_ID}'. "
        "MemorySanitizer is Clang-only, so other compilers are unsupported.")
endif()

# ---------------------------------------------------------------------------
# Core module sources. One static library per build config is produced from
# exactly these files so tests can link whichever config they need.
# ---------------------------------------------------------------------------
set(DTL_CORE_SOURCES
    src/core/err.c
    src/core/endian.c
    src/core/buf.c
    src/core/arena.c
    src/core/hexdump.c
)

# format module: DTL container + TLV framing (decode side). Depends on core.
set(DTL_FORMAT_SOURCES
    src/format/crc.c
    src/format/container.c
    src/format/tlv.c
    src/format/render.c
)

# codec module: compression codecs + registry. Depends on core.
set(DTL_CODEC_SOURCES
    src/codec/store.c
    src/codec/rle.c
    src/codec/varint.c
    src/codec/lz77.c
    src/codec/dict.c
    src/codec/delta.c
    src/codec/base32.c
    src/codec/registry.c
)

# records module: typed DTL record parsers + registry. Depends on core (and the
# format/tlv.h struct). Depends on format so it can carry usage requirements.
set(DTL_RECORDS_SOURCES
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
)

# crypto module: keyed hash, KDF, keystore, redaction. Depends on records (the
# redaction pass operates on parsed records) and thus transitively on core.
set(DTL_CRYPTO_SOURCES
    src/crypto/hash.c
    src/crypto/kdf.c
    src/crypto/keystore.c
    src/crypto/redact.c
    src/crypto/build_key.c
)

# query module: filter DSL (lexer -> parser -> AST -> evaluator). Depends on
# records (the evaluator resolves fields against parsed records).
set(DTL_QUERY_SOURCES
    src/query/lex.c
    src/query/ast.c
    src/query/parse.c
    src/query/eval.c
    src/query/query.c
)

# writer module: the DTL encoder. Depends on codec (section compression) and
# crypto (hmac trailer); crypto carries records/format/core.
set(DTL_WRITER_SOURCES
    src/writer/writer.c
)

# report module: container reporting and transformation tools (walk pipeline,
# stats, index, export, validate, diff, merge, split). Depends on writer
# (merge/split re-encode) and query's dependencies.
set(DTL_REPORT_SOURCES
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
)

# cli module: subcommand implementations behind the `dtl` front end. Links the
# whole decode pipeline plus crypto (redaction/hmac) and query.
set(DTL_CLI_SOURCES
    src/cli/cli.c
)

# Warnings applied to every target.
set(DTL_WARN_FLAGS -Wall -Wextra)

# ---------------------------------------------------------------------------
# Build-time device-key injection.
#
# DTL_SEED (a build variable) is turned into a generated header dtl_seed.h by the
# host tool tools/make_key; crypto/build_key.c includes it so the device key is
# KDF(DTL_SEED) at runtime -- procedural, never a hardcoded constant. Changing
# DTL_SEED and reconfiguring regenerates the header and changes the key.
# ---------------------------------------------------------------------------
set(DTL_SEED "telemetry-forge-dev-seed-v1"
    CACHE STRING "Seed the device key is derived from (KDF input).")
set(DTL_GEN_DIR "${CMAKE_BINARY_DIR}/gen")
set(DTL_SEED_HEADER "${DTL_GEN_DIR}/dtl_seed.h")

# Host tool: links the KDF + hash sources directly (it cannot link the crypto
# library, which itself depends on the header this tool generates).
add_executable(dtl_make_key
    tools/make_key.c
    src/crypto/kdf.c
    src/crypto/hash.c
    src/core/endian.c)
target_include_directories(dtl_make_key PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_options(dtl_make_key PRIVATE ${DTL_WARN_FLAGS})

add_custom_command(
    OUTPUT "${DTL_SEED_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${DTL_GEN_DIR}"
    COMMAND dtl_make_key "${DTL_SEED}" "${DTL_SEED_HEADER}"
    DEPENDS dtl_make_key
    COMMENT "Generating dtl_seed.h from DTL_SEED=\"${DTL_SEED}\""
    VERBATIM)
add_custom_target(dtl_gen_seed DEPENDS "${DTL_SEED_HEADER}")

# ---------------------------------------------------------------------------
# dtl_add_config(<suffix> COMPILE <flags...> LINK <flags...>)
#
# Produces, for one build configuration:
#   * static library  dtl_core<suffix>   from DTL_CORE_SOURCES
#   * smoke executable dtl_smoke<suffix>  from src/core/_smoke.c
#
# The three configurations described in the project spec map to:
#   suffix ""      -> config "dtl"       (release-ish, no sanitizer)
#   suffix "_asan" -> config "dtl_asan"  (ASan + UBSan)
#   suffix "_msan" -> config "dtl_msan"  (MSan with origin tracking)
#
# The src/ include root is attached as a PUBLIC usage requirement so it
# propagates to anything that links the core library (e.g. the smoke exe and
# future tests). Sanitizer flags are PUBLIC in both compile and link scope so
# consumers are instrumented and linked consistently with the library.
# ---------------------------------------------------------------------------
function(dtl_add_config suffix)
    cmake_parse_arguments(CFG "" "" "COMPILE;LINK" ${ARGN})

    set(core "dtl_core${suffix}")
    add_library(${core} STATIC ${DTL_CORE_SOURCES})
    target_include_directories(${core} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_options(${core} PUBLIC ${CFG_COMPILE})
    target_compile_options(${core} PRIVATE ${DTL_WARN_FLAGS})
    if(CFG_LINK)
        target_link_options(${core} PUBLIC ${CFG_LINK})
    endif()

    # format library for this config; usage requirements flow up from core.
    set(format "dtl_format${suffix}")
    add_library(${format} STATIC ${DTL_FORMAT_SOURCES})
    target_compile_options(${format} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${format} PUBLIC ${core})

    # core smoke exercises the core primitives directly.
    set(smoke "dtl_smoke${suffix}")
    add_executable(${smoke} src/core/_smoke.c)
    target_compile_options(${smoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${smoke} PRIVATE ${core})

    # format smoke parses hand-built containers and walks TLV streams.
    set(fsmoke "dtl_format_smoke${suffix}")
    add_executable(${fsmoke} src/format/_smoke.c)
    target_compile_options(${fsmoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${fsmoke} PRIVATE ${format})

    # codec library + smoke for this config.
    set(codec "dtl_codec${suffix}")
    add_library(${codec} STATIC ${DTL_CODEC_SOURCES})
    target_compile_options(${codec} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${codec} PUBLIC ${core})

    set(csmoke "dtl_codec_smoke${suffix}")
    add_executable(${csmoke} src/codec/_smoke.c)
    target_compile_options(${csmoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${csmoke} PRIVATE ${codec})

    # records library + smoke for this config. Links format (for format/tlv.h)
    # which in turn carries core.
    set(records "dtl_records${suffix}")
    add_library(${records} STATIC ${DTL_RECORDS_SOURCES})
    target_compile_options(${records} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${records} PUBLIC ${format})

    set(rsmoke "dtl_records_smoke${suffix}")
    add_executable(${rsmoke} src/records/_smoke.c)
    target_compile_options(${rsmoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${rsmoke} PRIVATE ${records})

    # crypto library + smoke for this config. Links records (redaction operates
    # on parsed records), which carries format and core.
    set(crypto "dtl_crypto${suffix}")
    add_library(${crypto} STATIC ${DTL_CRYPTO_SOURCES})
    target_compile_options(${crypto} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${crypto} PUBLIC ${records})
    # build_key.c includes the generated dtl_seed.h; ensure it exists first.
    target_include_directories(${crypto} PRIVATE "${DTL_GEN_DIR}")
    add_dependencies(${crypto} dtl_gen_seed)

    set(cysmoke "dtl_crypto_smoke${suffix}")
    add_executable(${cysmoke} src/crypto/_smoke.c)
    target_compile_options(${cysmoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${cysmoke} PRIVATE ${crypto})

    # query library + smoke for this config. Links records (the evaluator reads
    # parsed record fields), which carries format and core.
    set(query "dtl_query${suffix}")
    add_library(${query} STATIC ${DTL_QUERY_SOURCES})
    target_compile_options(${query} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${query} PUBLIC ${records})

    set(qsmoke "dtl_query_smoke${suffix}")
    add_executable(${qsmoke} src/query/_smoke.c)
    target_compile_options(${qsmoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${qsmoke} PRIVATE ${query})

    # writer library + round-trip smoke. Links codec and crypto; crypto carries
    # records/format/core, so the whole decode pipeline is available too.
    set(writer "dtl_writer${suffix}")
    add_library(${writer} STATIC ${DTL_WRITER_SOURCES})
    target_compile_options(${writer} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${writer} PUBLIC ${codec} ${crypto})

    set(wsmoke "dtl_writer_smoke${suffix}")
    add_executable(${wsmoke} src/writer/_smoke.c)
    target_compile_options(${wsmoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${wsmoke} PRIVATE ${writer})

    # report library + smoke for this config. Links writer (merge/split
    # re-encode records) which carries codec and crypto transitively.
    set(report "dtl_report${suffix}")
    add_library(${report} STATIC ${DTL_REPORT_SOURCES})
    target_compile_options(${report} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${report} PUBLIC ${writer} ${query})

    set(repsmoke "dtl_report_smoke${suffix}")
    add_executable(${repsmoke} src/report/_smoke.c)
    target_compile_options(${repsmoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${repsmoke} PRIVATE ${report})

    # cli library: the subcommand logic. Links query (carries records/format/
    # core) and crypto and codec so the whole pipeline is available, plus the
    # report tools exposed as subcommands.
    set(cli "dtl_cli${suffix}")
    add_library(${cli} STATIC ${DTL_CLI_SOURCES})
    target_compile_options(${cli} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${cli} PUBLIC ${query} ${codec} ${crypto} ${report})

    # The real `dtl` executable (and dtl_asan / dtl_msan variants).
    set(exe "dtl${suffix}")
    add_executable(${exe} src/cli/main.c)
    target_compile_options(${exe} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${exe} PRIVATE ${cli})

    # cli smoke: synthesizes files with the writer and drives the subcommands.
    set(clismoke "dtl_cli_smoke${suffix}")
    add_executable(${clismoke} src/cli/_smoke.c)
    target_compile_options(${clismoke} PRIVATE ${DTL_WARN_FLAGS})
    target_link_libraries(${clismoke} PRIVATE ${cli} ${writer})
endfunction()

# dtl        : -O2 -g, no sanitizer
dtl_add_config(""
    COMPILE -O2 -g)

# dtl_asan   : AddressSanitizer + UndefinedBehaviorSanitizer
dtl_add_config("_asan"
    COMPILE -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
    LINK    -fsanitize=address,undefined)

# dtl_msan   : MemorySanitizer with full origin tracking
dtl_add_config("_msan"
    COMPILE -O1 -g -fno-omit-frame-pointer -fsanitize=memory -fsanitize-memory-track-origins=2
    LINK    -fsanitize=memory)

# ---------------------------------------------------------------------------
# tools/gen_corpus: procedural DTL input generator (host build, no sanitizer).
# Links the plain writer library, which carries the whole pipeline.
# ---------------------------------------------------------------------------
add_executable(dtl_gen_corpus tools/gen_corpus.c)
target_compile_options(dtl_gen_corpus PRIVATE ${DTL_WARN_FLAGS})
target_link_libraries(dtl_gen_corpus PRIVATE dtl_writer)

# ---------------------------------------------------------------------------
# Test registration: every per-module smoke binary runs under ctest, in all
# three configurations (plain, ASan+UBSan, MSan).
# ---------------------------------------------------------------------------
enable_testing()

foreach(cfg "" "_asan" "_msan")
    add_test(NAME core_smoke${cfg} COMMAND dtl_smoke${cfg})
    foreach(mod format codec records crypto query writer report cli)
        add_test(NAME ${mod}_smoke${cfg}
                 COMMAND dtl_${mod}_smoke${cfg})
    endforeach()
endforeach()
