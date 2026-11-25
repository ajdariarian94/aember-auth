#include <aember-auth/base64.h>
#include <aember-auth/device-key.h>

#include <cerrno>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
#include <monocypher-ed25519.h>
#include <monocypher.h>
}

// Ed25519 (RFC 8032) is Monocypher's (third_party/monocypher, BSD-2-Clause):
// small, no TLS library needed for it.

namespace aember::auth {

namespace {

/// The 64-byte secret key (seed + public half) and the public key from the
/// 32-byte seed. Wipes its copies when it goes away.
struct Ed25519 {
  std::array<std::uint8_t, 64> secret{};
  std::array<std::uint8_t, 32> pub{};
  explicit Ed25519(const std::array<std::uint8_t, 32>& seed) {
    std::array<std::uint8_t, 32> copy = seed;  // key_pair wipes the seed
    crypto_ed25519_key_pair(secret.data(), pub.data(), copy.data());
  }
  ~Ed25519() { crypto_wipe(secret.data(), secret.size()); }
  Ed25519(const Ed25519&) = delete;
  Ed25519& operator=(const Ed25519&) = delete;
};

/// @p out filled from the kernel's random pool (blocks until it is seeded).
bool RandomBytes(std::span<std::uint8_t> out) {
  while (!out.empty()) {
    const ssize_t n = ::getrandom(out.data(), out.size(), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    out = out.subspan(static_cast<std::size_t>(n));
  }
  return true;
}

}  // namespace

std::expected<DeviceKey, std::string> DeviceKey::LoadOrCreate(
    const std::string& path) {
  DeviceKey k;
  if (std::ifstream in{path}) {
    std::stringstream text;
    text << in.rdbuf();
    std::string b64 = text.str();
    while (!b64.empty() && (b64.back() == '\n' || b64.back() == '\r')) {
      b64.pop_back();
    }
    const auto seed = Base64Decode(b64);
    if (!seed || seed->size() != k.seed_.size()) {
      return std::unexpected(std::format("{}: not a device key", path));
    }
    std::copy(seed->begin(), seed->end(), k.seed_.begin());
  } else {
    if (!RandomBytes(k.seed_)) return std::unexpected("random generator failed");

    std::error_code ec;
    const auto dir = std::filesystem::path{path}.parent_path();
    std::filesystem::create_directories(dir, ec);
    ::chmod(dir.c_str(), 0700);
    const std::string tmp = path + ".tmp";
    const int fd =
        ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return std::unexpected(std::format("cannot write {}", tmp));
    const std::string out = Base64Encode(k.seed_) + "\n";
    const bool written =
        ::write(fd, out.data(), out.size()) == static_cast<ssize_t>(out.size());
    ::fsync(fd);
    ::close(fd);
    if (!written || ::rename(tmp.c_str(), path.c_str()) != 0) {
      return std::unexpected(std::format("cannot write {}", path));
    }
  }
  const Ed25519 key{k.seed_};
  k.public_ = key.pub;
  return k;
}

DeviceKey::Signature DeviceKey::Sign(
    std::span<const std::uint8_t> message) const {
  Signature sig{};
  const Ed25519 key{seed_};
  crypto_ed25519_sign(sig.data(), key.secret.data(), message.data(),
                      message.size());
  return sig;
}

bool DeviceKey::Verify(const PublicKey& key,
                       std::span<const std::uint8_t> message,
                       const Signature& signature) {
  return crypto_ed25519_check(signature.data(), key.data(), message.data(),
                              message.size()) == 0;
}

}  // namespace aember::auth
