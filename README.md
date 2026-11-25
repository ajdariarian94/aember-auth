# aember-auth

The identity of an [aember](https://github.com/ajdariarian94/aember) device
towards an [aember-fleet](https://github.com/ajdariarian94/aember-fleet)
server, in a small LXC container (~2.7 MB: one binary and its TLS library).

- On its first start it makes an **Ed25519 device key**
  (`/var/lib/aember-auth/device.key`, 0600). The key never leaves the
  container.
- It **enrolls** once with a join token from the fleet admin; the server
  learns the public key and gives the device an id (kept in
  `/var/lib/aember-auth/device.json`).
- It **logs in** by signing a server challenge
  (`aember-auth-v1\n<device_id>\n<nonce>`) and gets a short-lived token,
  renewed when needed.
- Other services on the device reach the fleet server through its socket
  **`/run/aember-auth/auth.sock`** and never hold the key, a token or a TLS
  stack. Only `/api/v1/device/...` requests are forwarded.

TLS is mbedTLS (Apache-2.0) or, until the SDK carries mbedTLS, wolfSSL
(GPL-2.0-only; `-DAEMBER_AUTH_TLS=mbedtls|wolfssl`), the server's certificate
checked against the fleet's CA
(pinned, from the board's overlay) and its name.

## Socket protocol

One JSON line per connection:

```
{"op": "status"}
  -> {"ok": true, "enrolled": true, "device_id": "...", "server": "..."}
{"op": "request", "method": "GET", "path": "/api/v1/device/desired"}
  -> {"ok": true, "status": 200, "content_type": "application/json"}
     then the response body until the connection closes
```

Errors are `{"ok": false, "error": "..."}`.

## On a device

The board's overlay (`resources/<arch>/rootfs/` in aember) needs
`etc/aember/auth/auth.json` and the fleet's CA certificate:

```json
{
  "server": "https://fleet.example:8443",
  "connect": "10.0.2.2",
  "ca": "/etc/aember-auth/ca.pem",
  "join_token": "<from `aember-fleet join-token`>",
  "name": "kitchen-display"
}
```

`connect` is optional: an address to connect to while the certificate is
checked against the name in `server` (QEMU reaches its host at
10.0.2.2). `etc/aember/auth/ca.pem` is the fleet's `data/tls/ca.crt`. The
container binds `/etc/aember/auth` (read-only), `/var/lib/aember-auth` and
`/run/aember-auth` (`aember-container.json`).

## Build

In the dev container (aember's dev image):

```bash
git submodule update --init
aember-cli/run.py sdk   -a x64-poky-linux    # aember-resources SDK v0.1.15+
aember-cli/run.py build -a x64-poky-linux
aember-cli/run.py pack  -a x64-poky-linux
aember-cli/run.py install -a x64-poky-linux ../aember
aember-cli/run.py test                       # unit tests (x64 SDK)
```

Every aember target works (`-a aarch64-poky-linux`, `-musl` variants, ...).

## Fuzzing

Every input from outside the process (the local socket, the fleet server's
answers, auth.json and the state files) has a libFuzzer target in `fuzz/`.
On Ubuntu 24.04:

```bash
sudo apt-get install clang-18 llvm-18 libclang-rt-18-dev cmake ninja-build \
    pkg-config libmbedtls-dev nlohmann-json3-dev
fuzz/run.sh            # every target for 60 s (CI does the same)
fuzz/run.sh 600 fuzz_socket
```

Crashing inputs land in `build/fuzz/crashes/<target>/`; replay one with
`build/fuzz/fuzz_<target> <file>`.
