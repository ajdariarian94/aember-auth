// auth.json as main() reads it: any text, then ParseAuthConfig.
#include <cstdint>
#include <cstdlib>

#include <aember-auth/fleet-client.h>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace aember::auth;
  const auto j = nlohmann::json::parse(data, data + size, nullptr, false);
  const auto c = ParseAuthConfig(j.is_discarded() ? nlohmann::json{} : j);
  if (c && (c->server.empty() || !ParseUrl(c->server))) std::abort();
  return 0;
}
