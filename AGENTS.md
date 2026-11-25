# AGENTS.md

Guidance for AI coding agents working in **aember-auth**.

## What this is

A C++23 service in an aember LXC container: the device's identity towards
aember-fleet (see README.md). Same layout and CLI as aember-stats and
aember-monitor: `aember-cli/run.py` runs aember-build-helper's shared
`project-cli/` and only sets what differs (
`TESTS = "sdk"`, `RESOURCES_VERSION = "0.1.15"`, the first release whose
SDKs have wolfSSL and nlohmann/json).

```
include/aember-auth/   base64.h, device-key.h (Ed25519, wolfCrypt), http.h
                       (HTTP/1.1 over TCP/TLS), fleet-client.h (enroll,
                       login, requests), server.h (the Unix socket)
src/                   the same + main.cpp
tests/                 *-unittest via CTest; check.h (the SDK has no test
                       framework); test_fleet.cpp runs a fake fleet server
fuzz/                  libFuzzer targets (host clang build, ASan + UBSan),
                       seed corpus + dictionaries in fuzz/corpus/, run.sh
aember-container.json  the container (binds, restart policy)
tools/aember-build-helper  submodule: packs the container
```

## Rules

- The device key never leaves this process: no API returns it, the socket
  only forwards requests. Keep it that way.
- The socket forwards only `/api/v1/device/` paths (no `..`): a local
  client gets the device's rights, not enrollment.
- The challenge message `aember-auth-v1\n<device_id>\n<nonce>` and the API
  paths are an interface with aember-fleet's server
  (`server/aember_fleet/security.py`, `app.py`): change both together.
- wolfSSL: include `<wolfssl/options.h>` first. Its compatibility macros
  rename common words (`Sha256` is `wc_Sha256`); don't name classes like
  them. `wc_ed25519_make_public` derives from an imported private key.
- Tests build with the x64 SDK and run through its loader
  (`aember-cli/run.py test`). Locally, against an unreleased SDK:
  `AEMBER_RESOURCES_DIR=/aember_ws/aember-resources/yocto/build`.
- A test that pins down a fixed bug starts with a comment
  `Regression: <the bug>` (`grep -rn "Regression:"` lists them). Every bug
  fix gets one.
- Fuzzing: `fuzz/run.sh [SECONDS] [TARGET...]` (CI: 60 s per target, the
  `fuzz` job). It is a host build with clang 18 and Ubuntu's wolfSSL and
  nlohmann-json, not the SDK (it has no clang/libFuzzer). Targets cover
  every input from outside the process: the socket (`fuzz_socket`), the
  fleet server's answers through a fake server (`fuzz_fleet_responses`),
  HTTP parsing, URLs, base64, auth.json, device.key/device.json. A new
  parser gets a target; a crash gets a fix, a `Regression:` unit test, and
  its input in `fuzz/corpus/<target>/`. nlohmann/json: `value()` and
  `get<T>()` throw on another type, and `dump()` throws on invalid UTF-8;
  check types (`is_string()` ...) and dump text from outside with
  `error_handler_t::replace`.
- Property-based tests: `tests/property.h` (`ForAll(name, runs, [](Gen&
  g) {...})`, seeded cases, no framework; a failing case prints the seed,
  `AEMBER_PROPERTY_SEED=<seed> AEMBER_PROPERTY_RUNS=1` reruns it, a big
  `AEMBER_PROPERTY_RUNS` runs more) in `tests/test_properties.cpp`: base64,
  HTTP responses in every framing read from pieces of random sizes, URLs,
  signatures, the challenge message. A new parser or format gets a
  round-trip property next to its fuzz target.
- Commit as Arian Ajdari; branches + PRs; merge when tests pass.
