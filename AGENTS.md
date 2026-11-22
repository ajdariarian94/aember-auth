# AGENTS.md

Guidance for AI coding agents working in **aember-auth**.

## What this is

A C++23 service in an aember LXC container: the device's identity towards
aember-fleet (see README.md). Same layout and CLI as aember-stats and
aember-monitor (`aember-cli/`, shared; only `project.py` differs:
`TESTS = "sdk"`, `RESOURCES_VERSION = "0.1.15"`, the first release whose
SDKs have wolfSSL and nlohmann/json).

```
include/aember-auth/   base64.h, device-key.h (Ed25519, wolfCrypt), http.h
                       (HTTP/1.1 over TCP/TLS), fleet-client.h (enroll,
                       login, requests), server.h (the Unix socket)
src/                   the same + main.cpp
tests/                 *-unittest via CTest; check.h (the SDK has no test
                       framework); test_fleet.cpp runs a fake fleet server
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
- Commit as Arian Ajdari; branches + PRs; merge when tests pass.
