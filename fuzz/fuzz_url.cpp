// ParseUrl (auth.json's "server"): a parsed URL has a host and a valid port.
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <aember-auth/http.h>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  const auto url = aember::auth::ParseUrl(
      std::string_view{reinterpret_cast<const char*>(data), size});
  if (url && (url->host.empty() || url->port <= 0 || url->port > 65535)) {
    std::abort();
  }
  return 0;
}
