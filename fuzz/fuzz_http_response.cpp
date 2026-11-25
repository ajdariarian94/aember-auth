// ReadHttpResponse on any bytes from the fleet server, read in pieces of a
// fuzzed size (as TLS records arrive), with and without a body sink.
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include <aember-auth/http.h>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace aember::auth;
  if (size < 1) return 0;
  const std::size_t piece = (data[0] & 0x7f) + 1;
  const bool use_sink = data[0] & 0x80;
  std::string_view rest{reinterpret_cast<const char*>(data + 1), size - 1};
  const ByteSource source = [&](char* buf, std::size_t n) -> ssize_t {
    const auto k = std::min({n, piece, rest.size()});
    std::memcpy(buf, rest.data(), k);
    rest.remove_prefix(k);
    return static_cast<ssize_t>(k);
  };
  std::string sunk;
  bool head_seen = false;
  const auto r = ReadHttpResponse(
      source,
      use_sink ? BodySink{[&](std::string_view c) {
        if (!head_seen) std::abort();  // the head comes first
        sunk.append(c);
        return sunk.size() < 1 << 20;
      }}
               : BodySink{},
      [&](const HttpResponse&) { head_seen = true; });
  if (r && use_sink && !r->body.empty()) std::abort();
  if (r && !head_seen) std::abort();
  return 0;
}
