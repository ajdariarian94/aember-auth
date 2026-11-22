#include <algorithm>
#include <cstring>
#include <memory>

#include "check.h"
#include <aember-auth/http.h>

using namespace aember::auth;

namespace {

/// Serves @p data in pieces of @p step bytes.
ByteSource Source(std::string data, std::size_t step = 7) {
  auto pos = std::make_shared<std::size_t>(0);
  auto text = std::make_shared<std::string>(std::move(data));
  return [=](char* buf, std::size_t n) -> ssize_t {
    const auto take = std::min({n, step, text->size() - *pos});
    std::memcpy(buf, text->data() + *pos, take);
    *pos += take;
    return static_cast<ssize_t>(take);
  };
}

}  // namespace

int main() {
  {  // Content-Length, header names lower-case, the head callback first
    int heads = 0;
    auto r = ReadHttpResponse(
        Source("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
               "Content-Length: 11\r\n\r\n{\"a\": true}trailing"),
        {},
        [&](const HttpResponse& h) {
          ++heads;
          CHECK_EQ(h.status, 200);
        });
    CHECK(r.has_value());
    CHECK_EQ(heads, 1);
    if (r) {
      CHECK_EQ(r->headers["content-type"], std::string{"application/json"});
      CHECK_EQ(r->body, std::string{"{\"a\": true}"});
    }
  }
  {  // chunked, into a sink
    std::string got;
    auto r = ReadHttpResponse(
        Source("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
               "5\r\nhello\r\n7;ext=1\r\n, world\r\n0\r\n\r\n",
               3),
        [&](std::string_view c) {
          got.append(c);
          return true;
        });
    CHECK(r.has_value());
    CHECK_EQ(got, std::string{"hello, world"});
    if (r) CHECK(r->body.empty());
  }
  {  // no length: until the end
    auto r = ReadHttpResponse(Source("HTTP/1.0 404 Not Found\r\n\r\nnope"));
    CHECK(r.has_value());
    if (r) {
      CHECK_EQ(r->status, 404);
      CHECK_EQ(r->body, std::string{"nope"});
    }
  }
  {  // a sink that says stop aborts
    auto r = ReadHttpResponse(
        Source("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd"),
        [](std::string_view) { return false; });
    CHECK(!r.has_value());
  }
  for (const auto* bad :
       {"",
        "SSH-2.0-dropbear\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"}) {
    CHECK(!ReadHttpResponse(Source(bad)).has_value());
  }

  // URLs
  {
    auto u = ParseUrl("https://fleet.example:8443");
    CHECK(u.has_value());
    if (u) {
      CHECK(u->tls);
      CHECK_EQ(u->host, std::string{"fleet.example"});
      CHECK_EQ(u->port, 8443);
    }
    auto h = ParseUrl("http://10.0.2.2/");
    CHECK(h.has_value());
    if (h) {
      CHECK(!h->tls);
      CHECK_EQ(h->port, 80);
    }
    CHECK_EQ(ParseUrl("https://x")->port, 443);
    for (const auto* bad : {"ftp://x",
                            "https://",
                            "https://x:0",
                            "https://x:99999",
                            "https://x/api"}) {
      CHECK(!ParseUrl(bad).has_value());
    }
  }
  return Failures();
}
