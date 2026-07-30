# Security policy

## Scope

telemetry-forge parses untrusted binary containers. The decode pipeline
(container parse, codec decode, TLV framing, record parse) is written to be
memory-safe on adversarial input: every length is checked against the bytes
remaining, and the tree is continuously exercised under AddressSanitizer,
UndefinedBehaviorSanitizer, and MemorySanitizer, including the
ClusterFuzzLite harnesses in `fuzz/`.

## Reporting a vulnerability

Please report suspected memory-safety or integrity issues privately to the
repository owner rather than opening a public issue. Include the input file
that triggers the problem, the sanitizer report (if any), and the commit you
built from.

## HMAC keys

The device key is derived from the `DTL_SEED` build variable. Never ship a
product build with the default development seed; set `DTL_SEED` to a secret
value at configure time. `DTL_SEED` is a build-time secret, not a runtime
one: anyone with the exact build inputs can reproduce the key.
