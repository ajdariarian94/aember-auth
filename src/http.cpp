#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <optional>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <aember-auth/http.h>

#include "tls.h"

namespace aember::auth {

namespace {

std::string Lower(std::string_view s) {
  std::string out{s};
  std::ranges::transform(out, out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

std::string_view Trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
    s.remove_prefix(1);
  while (!s.empty() &&
         (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
    s.remove_suffix(1);
  }
  return s;
}

/// Buffered reads from a ByteSource.
class Reader {
 public:
  explicit Reader(const ByteSource& source) : source_(source) {}

  /// Next line without "\r\n"; nullopt at the end or on error.
  std::optional<std::string> Line() {
    std::string line;
    while (true) {
      if (pos_ == buf_.size() && !Fill()) return std::nullopt;
      const auto nl = buf_.find('\n', pos_);
      if (nl == std::string::npos) {
        line.append(buf_, pos_);
        pos_ = buf_.size();
        if (line.size() > 16 * 1024) return std::nullopt;
        continue;
      }
      line.append(buf_, pos_, nl - pos_);
      pos_ = nl + 1;
      if (!line.empty() && line.back() == '\r') line.pop_back();
      return line;
    }
  }

  /// Up to @p max bytes (at least one unless at the end).
  std::optional<std::string_view> Some(std::size_t max) {
    if (pos_ == buf_.size() && !Fill()) return std::nullopt;
    const auto n = std::min(max, buf_.size() - pos_);
    std::string_view out{buf_.data() + pos_, n};
    pos_ += n;
    return out;
  }

  bool failed() const { return failed_; }

 private:
  bool Fill() {
    buf_.resize(16 * 1024);
    const ssize_t n = source_(buf_.data(), buf_.size());
    if (n < 0) failed_ = true;
    buf_.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
    pos_ = 0;
    return n > 0;
  }

  const ByteSource& source_;
  std::string buf_;
  std::size_t pos_ = 0;
  bool failed_ = false;
};

bool Deliver(HttpResponse& r, const BodySink& sink, std::string_view chunk) {
  if (sink) return sink(chunk);
  r.body.append(chunk);
  return true;
}

}  // namespace

std::expected<Url, std::string> ParseUrl(std::string_view text) {
  Url url;
  if (text.starts_with("https://")) {
    text.remove_prefix(8);
  } else if (text.starts_with("http://")) {
    text.remove_prefix(7);
    url.tls = false;
    url.port = 80;
  } else {
    return std::unexpected(std::format("'{}': want https:// or http://", text));
  }
  if (text.ends_with('/')) text.remove_suffix(1);
  if (text.find('/') != std::string_view::npos) {
    return std::unexpected("server URL can't have a path");
  }
  const auto colon = text.rfind(':');
  url.host = std::string{text.substr(0, colon)};
  if (colon != std::string_view::npos) {
    const auto port = text.substr(colon + 1);
    int p = 0;
    const auto [ptr, ec] =
        std::from_chars(port.data(), port.data() + port.size(), p);
    if (ec != std::errc{} || ptr != port.data() + port.size() || p <= 0 ||
        p > 65535) {
      return std::unexpected(std::format("bad port '{}'", port));
    }
    url.port = p;
  }
  if (url.host.empty()) return std::unexpected("no host in the server URL");
  return url;
}

std::expected<HttpResponse, std::string> ReadHttpResponse(
    const ByteSource& source, const BodySink& sink, const HeadSink& on_head) {
  Reader in{source};
  HttpResponse r;
  const auto status = in.Line();
  if (!status || !status->starts_with("HTTP/1.")) {
    return std::unexpected("no HTTP response");
  }
  const auto sp = status->find(' ');
  if (sp == std::string::npos ||
      std::from_chars(
          status->data() + sp + 1, status->data() + status->size(), r.status)
              .ec != std::errc{}) {
    return std::unexpected("bad status line: " + *status);
  }
  while (true) {
    const auto line = in.Line();
    if (!line) return std::unexpected("headers cut off");
    if (line->empty()) break;
    const auto colon = line->find(':');
    if (colon == std::string::npos) continue;
    r.headers[Lower(Trim(std::string_view{*line}.substr(0, colon)))] =
        std::string{Trim(std::string_view{*line}.substr(colon + 1))};
  }
  if (on_head) on_head(r);

  if (r.headers.contains("transfer-encoding") &&
      Lower(r.headers["transfer-encoding"]).find("chunked") !=
          std::string::npos) {
    while (true) {
      const auto size_line = in.Line();
      if (!size_line) return std::unexpected("chunked body cut off");
      std::size_t size = 0;
      const auto hex =
          Trim(std::string_view{*size_line}.substr(0, size_line->find(';')));
      if (std::from_chars(hex.data(), hex.data() + hex.size(), size, 16).ec !=
          std::errc{}) {
        return std::unexpected("bad chunk size");
      }
      if (size == 0) break;
      while (size > 0) {
        const auto piece = in.Some(size);
        if (!piece) return std::unexpected("chunk cut off");
        if (!Deliver(r, sink, *piece))
          return std::unexpected("transfer aborted");
        size -= piece->size();
      }
      if (!in.Line()) return std::unexpected("chunk cut off");  // its CRLF
    }
    return r;
  }

  if (r.headers.contains("content-length")) {
    std::size_t left = 0;
    const auto& v = r.headers["content-length"];
    if (std::from_chars(v.data(), v.data() + v.size(), left).ec !=
        std::errc{}) {
      return std::unexpected("bad Content-Length");
    }
    while (left > 0) {
      const auto piece = in.Some(left);
      if (!piece) return std::unexpected("body cut off");
      if (!Deliver(r, sink, *piece)) return std::unexpected("transfer aborted");
      left -= piece->size();
    }
    return r;
  }

  while (const auto piece = in.Some(64 * 1024)) {  // until the end
    if (!Deliver(r, sink, *piece)) return std::unexpected("transfer aborted");
  }
  if (in.failed()) return std::unexpected("read failed");
  return r;
}

// ---------------------------------------------------------------------------

namespace {

int Connect(const std::string& host, int port) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* list = nullptr;
  if (::getaddrinfo(
          host.c_str(), std::to_string(port).c_str(), &hints, &list) != 0) {
    return -1;
  }
  int fd = -1;
  for (auto* a = list; a != nullptr && fd < 0; a = a->ai_next) {
    fd = ::socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
    if (fd < 0) continue;
    timeval tv{30, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, a->ai_addr, a->ai_addrlen) != 0) {
      ::close(fd);
      fd = -1;
    }
  }
  ::freeaddrinfo(list);
  return fd;
}

}  // namespace

HttpClient::HttpClient(Url url, std::string ca_file, std::string connect_host)
    : url_(std::move(url)),
      ca_file_(std::move(ca_file)),
      connect_host_(std::move(connect_host)) {}

std::expected<HttpResponse, std::string> HttpClient::Request(
    std::string_view method, std::string_view path, const Headers& headers,
    std::string_view body, const BodySink& sink,
    const HeadSink& on_head) const {
  const std::string& host = connect_host_.empty() ? url_.host : connect_host_;
  const int fd = Connect(host, url_.port);
  if (fd < 0) {
    return std::unexpected(
        std::format("cannot connect to {}:{}", host, url_.port));
  }
  struct Fd {
    int fd;
    ~Fd() { ::close(fd); }
  } guard{fd};

  std::string request = std::format(
      "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n"
      "User-Agent: aember-auth\r\nContent-Length: {}\r\n",
      method,
      path,
      url_.host,
      body.size());
  for (const auto& [name, value] : headers) {
    request += std::format("{}: {}\r\n", name, value);
  }
  request += "\r\n";
  request.append(body);

  if (!url_.tls) {
    std::string_view out = request;
    while (!out.empty()) {
      const ssize_t n = ::send(fd, out.data(), out.size(), MSG_NOSIGNAL);
      if (n <= 0) return std::unexpected("send failed");
      out.remove_prefix(static_cast<std::size_t>(n));
    }
    return ReadHttpResponse(
        [fd](char* buf, std::size_t n) { return ::recv(fd, buf, n, 0); },
        sink,
        on_head);
  }

  auto tls = TlsConnect(fd, url_.host, ca_file_);
  if (!tls) return std::unexpected(tls.error());
  if (!(*tls)->WriteAll(request)) return std::unexpected("TLS write failed");
  TlsStream* stream = tls->get();
  return ReadHttpResponse(
      [stream](char* buf, std::size_t n) { return stream->Read(buf, n); },
      sink,
      on_head);
}

}  // namespace aember::auth
