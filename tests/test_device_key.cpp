#include <filesystem>
#include <fstream>

#include <sys/stat.h>

#include "check.h"
#include <aember-auth/base64.h>
#include <aember-auth/device-key.h>

using namespace aember::auth;

int main() {
  char dir[] = "/tmp/aember-auth-key-XXXXXX";
  if (::mkdtemp(dir) == nullptr) return 1;
  const std::string path = std::string{dir} + "/state/device.key";

  auto first = DeviceKey::LoadOrCreate(path);
  CHECK(first.has_value());
  struct stat st {};
  CHECK(::stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
  auto again = DeviceKey::LoadOrCreate(path);  // same key from the file
  CHECK(again.has_value());
  if (first && again) {
    CHECK(first->Public() == again->Public());
    const std::string msg = "aember-auth-v1\ndevice\nnonce";
    const std::span<const std::uint8_t> m{
        reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()};
    const auto sig = first->Sign(m);
    CHECK(DeviceKey::Verify(first->Public(), m, sig));
    CHECK(DeviceKey::Verify(again->Public(), m, again->Sign(m)));
    auto bad = sig;
    bad[10] ^= 1;
    CHECK(!DeviceKey::Verify(first->Public(), m, bad));
    std::string other = msg + "!";
    CHECK(!DeviceKey::Verify(
        first->Public(),
        {reinterpret_cast<const std::uint8_t*>(other.data()), other.size()},
        sig));
  }
  // RFC 8032 test 1: the public key of an all-known seed.
  {
    const std::string seed_hex =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < 32; ++i) {
      seed[i] = static_cast<std::uint8_t>(
          std::stoi(seed_hex.substr(2 * i, 2), nullptr, 16));
    }
    const std::string rfc = std::string{dir} + "/rfc.key";
    std::ofstream{rfc} << Base64Encode(seed) << "\n";
    auto k = DeviceKey::LoadOrCreate(rfc);
    CHECK(k.has_value());
    if (k) {
      CHECK_EQ(Base64Encode(k->Public()),
               std::string{"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="});
    }
  }
  std::ofstream{std::string{dir} + "/junk.key"} << "not a key\n";
  CHECK(!DeviceKey::LoadOrCreate(std::string{dir} + "/junk.key").has_value());
  std::filesystem::remove_all(dir);
  return Failures();
}
