#include "check.h"
#include <aember-auth/base64.h>

using namespace aember::auth;

namespace {
std::vector<std::uint8_t> Bytes(std::string_view s) {
  return {s.begin(), s.end()};
}
}  // namespace

int main() {
  // RFC 4648 test vectors.
  const std::pair<std::string_view, std::string_view> vectors[] = {
      {"", ""},
      {"f", "Zg=="},
      {"fo", "Zm8="},
      {"foo", "Zm9v"},
      {"foob", "Zm9vYg=="},
      {"fooba", "Zm9vYmE="},
      {"foobar", "Zm9vYmFy"}};
  for (const auto& [plain, encoded] : vectors) {
    CHECK_EQ(Base64Encode(Bytes(plain)), std::string{encoded});
    const auto back = Base64Decode(encoded);
    CHECK(back.has_value());
    if (back) CHECK(*back == Bytes(plain));
  }
  std::vector<std::uint8_t> all(256);
  for (int i = 0; i < 256; ++i) all[i] = static_cast<std::uint8_t>(i);
  CHECK(Base64Decode(Base64Encode(all)) == all);
  for (const auto* bad : {"Zg=", "Z===", "Zm9v!A==", "Zg==Zg==", "=Zg="}) {
    CHECK(!Base64Decode(bad).has_value());
  }
  return Failures();
}
