/**
 * @file http.h
 * @brief A small HTTP/1.1 client (one request per connection) over TCP or
 *        TLS (wolfSSL, the server checked against a pinned CA certificate).
 *        Enough for aember-auth's JSON calls and for streaming downloads
 *        through to local clients.
 */
#pragma once

#include <expected>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/types.h>

namespace aember::auth {

struct Url {
  bool tls = true;
  std::string host;  ///< also the TLS server name (SNI, certificate check)
  int port = 443;
};

/// "https://host[:port]" or "http://host[:port]" (no path).
std::expected<Url, std::string> ParseUrl(std::string_view text);

struct HttpResponse {
  int status = 0;
  std::map<std::string, std::string> headers;  ///< names lower-case
  std::string body;  ///< empty when the body went to a sink
};

/// Receives the body in pieces; false aborts the transfer.
using BodySink = std::function<bool(std::string_view chunk)>;
/// Called once status and headers are known, before any body piece.
using HeadSink = std::function<void(const HttpResponse& head)>;

/// Reads up to n bytes into buf: count, 0 at the end, <0 on error.
using ByteSource = std::function<ssize_t(char* buf, std::size_t n)>;

/// Parse a response from @p source: status line, headers, then the body by
/// Content-Length, chunked encoding or until the end. With @p sink the body
/// goes there instead of HttpResponse::body.
std::expected<HttpResponse, std::string> ReadHttpResponse(
    const ByteSource& source, const BodySink& sink = {},
    const HeadSink& on_head = {});

using Headers = std::vector<std::pair<std::string, std::string>>;

class HttpClient {
 public:
  /// @p ca_file: PEM CA certificate(s) the server's certificate must chain
  /// to (https only). @p connect_host: where to connect, if not url.host
  /// (the certificate is still checked against url.host).
  HttpClient(Url url, std::string ca_file, std::string connect_host = {});

  std::expected<HttpResponse, std::string> Request(
      std::string_view method, std::string_view path, const Headers& headers,
      std::string_view body, const BodySink& sink = {},
      const HeadSink& on_head = {}) const;

  [[nodiscard]] const Url& url() const { return url_; }

 private:
  Url url_;
  std::string ca_file_;
  std::string connect_host_;
};

}  // namespace aember::auth
