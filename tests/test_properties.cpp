// Property-based tests (tests/property.h): base64, HTTP responses in any
// framing and split into any pieces, server URLs, device-key signatures
// and the challenge message.
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <format>
#include <map>
#include <memory>

#include "check.h"
#include "property.h"
#include <aember-auth/base64.h>
#include <aember-auth/device-key.h>
#include <aember-auth/fleet-client.h>
#include <aember-auth/http.h>

using namespace aember::auth;
using property::ForAll;
using property::Gen;

namespace {

std::span<const std::uint8_t> Span(const std::string& s) {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

/// Serves @p data in pieces of random sizes (1 .. 40 bytes, or the rest);
/// the pieces are drawn up front so the source owns no generator.
ByteSource Pieces(std::string data, Gen& g) {
  auto steps = std::make_shared<std::vector<std::size_t>>();
  for (std::size_t n = 0; n < data.size();) {
    steps->push_back(
        static_cast<std::size_t>(g.Chance(0.1) ? 1 << 20 : g.Int(1, 40)));
    n += steps->back();
  }
  auto text = std::make_shared<std::string>(std::move(data));
  auto pos = std::make_shared<std::size_t>(0);
  auto i = std::make_shared<std::size_t>(0);
  return [=](char* buf, std::size_t n) -> ssize_t {
    if (*pos == text->size()) return 0;
    const auto take = std::min({n, (*steps)[(*i)++], text->size() - *pos});
    std::memcpy(buf, text->data() + *pos, take);
    *pos += take;
    return static_cast<ssize_t>(take);
  };
}

constexpr std::string_view kToken =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!#$%&'*+^"
    "`|~";

}  // namespace

int main() {
  ForAll("base64 round trip", 500, [](Gen& g) {
    const auto data = g.Bytes(100);
    const auto text = Base64Encode(Span(data));
    CHECK_EQ(text.size(), (data.size() + 2) / 3 * 4);
    const auto back = Base64Decode(text);
    CHECK(back.has_value() && std::string(back->begin(), back->end()) == data);
  });

  ForAll("base64: any text decodes to nothing or to bytes that encode back",
         1000,
         [](Gen& g) {
           const auto text = g.Text("AZaz09+/=-_ \n", 0, 24);
           const auto bytes = Base64Decode(text);
           if (!bytes) return;
           CHECK_EQ(text.size() % 4, 0u);
           CHECK(Base64Decode(Base64Encode(*bytes)) == bytes);
         });

  // An HTTP response with random status, headers and body, framed by
  // Content-Length, chunked encoding (random chunk sizes, extensions) or
  // the end of the stream, read from pieces of random sizes: the parser
  // gives back what was sent, into HttpResponse::body or a sink.
  ForAll("HTTP responses in any framing and any pieces", 500, [](Gen& g) {
    const int status = g.Int(100, 599);
    std::map<std::string, std::string> headers;
    for (int i = g.Size(5); i > 0; --i) {
      auto name = g.Text(kToken, 1, 12);
      std::ranges::transform(name, name.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      if (name == "content-length" || name == "transfer-encoding") continue;
      // Values: no CR/LF, no blanks at either end (they are trimmed).
      auto value = g.Text("abc xyz,;=/\"0123456789\t", 0, 20);
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.erase(0, 1);
      while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
        value.pop_back();
      headers[name] = value;
    }
    const auto body = g.Bytes(300);
    const int framing = g.Int(0, 2);  // length, chunked, until the end
    std::string text =
        std::format("HTTP/1.{} {} Whatever\r\n", g.Int(0, 1), status);
    for (const auto& [name, value] : headers) {
      auto shown = name;  // header names in any case
      for (auto& c : shown)
        if (g.Chance(0.3))
          c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
      text +=
          std::format("{}:{}{}\r\n", shown, g.Chance(0.5) ? " " : "", value);
    }
    if (framing == 0)
      text += std::format("Content-Length: {}\r\n", body.size());
    if (framing == 1) text += "Transfer-Encoding: chunked\r\n";
    text += "\r\n";
    if (framing == 1) {
      for (std::size_t pos = 0; pos < body.size();) {
        const auto n = std::min<std::size_t>(g.Int(1, 64), body.size() - pos);
        text += std::format("{:x}{}\r\n", n, g.Chance(0.2) ? ";ext=1" : "");
        text += body.substr(pos, n) + "\r\n";
        pos += n;
      }
      text += "0\r\n\r\n";
    } else {
      text += body;
    }
    const bool to_sink = g.Chance(0.5);
    std::string sunk;
    const auto r = ReadHttpResponse(Pieces(text, g),
                                    to_sink ? BodySink{[&](std::string_view c) {
                                      sunk.append(c);
                                      return true;
                                    }}
                                            : BodySink{});
    CHECK(r.has_value());
    if (!r) return;
    CHECK_EQ(r->status, status);
    CHECK_EQ(to_sink ? sunk : r->body, body);
    if (to_sink) CHECK(r->body.empty());
    for (const auto& [name, value] : headers) {
      const auto it = r->headers.find(name);
      CHECK(it != r->headers.end() && it->second == value);
    }
  });

  ForAll("HTTP: any bytes are a response or an error, never a crash",
         1000,
         [](Gen& g) {
           auto text = g.Pick(std::vector<std::string>{
               "",
               "HTTP/1.1 200 OK\r\n",
               "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"});
           text += g.Bytes(60);
           std::ignore = ReadHttpResponse(Pieces(text, g));
         });

  ForAll("server URLs give back scheme, host and port", 500, [](Gen& g) {
    const bool tls = g.Chance(0.5);
    const auto host = g.Text("abcdefghijklmnopqrstuvwxyz0123456789.-", 1, 30);
    const bool with_port = g.Chance(0.6);
    const int port = g.Int(1, 65535);
    const auto text = std::format("{}://{}{}{}",
                                  tls ? "https" : "http",
                                  host,
                                  with_port ? std::format(":{}", port) : "",
                                  g.Chance(0.2) ? "/" : "");
    const auto url = ParseUrl(text);
    CHECK(url.has_value());
    if (!url) return;
    CHECK_EQ(url->tls, tls);
    CHECK_EQ(url->host, host);
    CHECK_EQ(url->port, with_port ? port : (tls ? 443 : 80));
  });

  ForAll("server URLs: bad ports and paths are refused", 300, [](Gen& g) {
    const auto port = g.Pick(std::vector<std::string>{
        "0", "65536", "-1", "", "80a", "99999999999", " 1"});
    CHECK(!ParseUrl("https://fleet" + (g.Chance(0.5) ? ":" + port : ":1/x"))
               .has_value());
  });

  char dir[] = "/tmp/aember-auth-prop-XXXXXX";
  if (::mkdtemp(dir) == nullptr) return 1;
  const auto key = DeviceKey::LoadOrCreate(std::string{dir} + "/device.key");
  CHECK(key.has_value());
  if (key) {
    ForAll("signatures verify; any changed byte is refused", 200, [&](Gen& g) {
      const auto message = ChallengeMessage(g.Text("0123456789abcdef", 1, 16),
                                            g.Text(kToken, 1, 32));
      auto sig = key->Sign(Span(message));
      CHECK(DeviceKey::Verify(key->Public(), Span(message), sig));
      auto changed = message;
      changed[static_cast<std::size_t>(
          g.Int(0, static_cast<int>(changed.size()) - 1))] ^=
          static_cast<char>(g.Int(1, 255));
      CHECK(!DeviceKey::Verify(key->Public(), Span(changed), sig));
      sig[static_cast<std::size_t>(g.Int(0, 63))] ^=
          static_cast<std::uint8_t>(g.Int(1, 255));
      CHECK(!DeviceKey::Verify(key->Public(), Span(message), sig));
    });
  }
  std::filesystem::remove_all(dir);

  ForAll("the challenge message is what the server checks", 200, [](Gen& g) {
    // aember-fleet's security.challenge_message: prefix, id, nonce, one
    // line each.
    const auto id = g.Text("0123456789abcdef", 0, 16);
    const auto nonce = g.Text(kToken, 0, 32);
    CHECK_EQ(ChallengeMessage(id, nonce),
             std::string{"aember-auth-v1\n"} + id + "\n" + nonce);
  });
  return Failures();
}
