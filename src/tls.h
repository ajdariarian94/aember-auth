/**
 * @file tls.h
 * @brief The TLS client under HttpClient, with one backend chosen at build
 *        time (CMake AEMBER_AUTH_TLS): mbedTLS (Apache-2.0) or wolfSSL
 *        (GPL-2.0-only, kept until the SDK carries mbedTLS). Both check the
 *        server's certificate against a pinned CA file and its name.
 */
#pragma once

#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include <sys/types.h>

namespace aember::auth {

class TlsStream {
 public:
  virtual ~TlsStream() = default;
  /// Up to @p n bytes: count, 0 at the end of the stream, <0 on error.
  virtual ssize_t Read(char* buf, std::size_t n) = 0;
  virtual bool WriteAll(std::string_view data) = 0;
};

/// Handshake on the connected socket @p fd (not taken over: the caller
/// closes it after the stream is gone). @p host: the server name for SNI and
/// the certificate check; @p ca_file: PEM CA certificate(s).
std::expected<std::unique_ptr<TlsStream>, std::string> TlsConnect(
    int fd, const std::string& host, const std::string& ca_file);

/// The backend's name, e.g. "mbedTLS 3.6.4" (logs, tests).
std::string TlsBackend();

}  // namespace aember::auth
