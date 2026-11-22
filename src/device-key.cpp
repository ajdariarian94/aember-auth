#include <aember-auth/base64.h>
#include <aember-auth/device-key.h>

// wolfSSL's options.h first: it carries the build's feature macros.
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfssl/wolfcrypt/ed25519.h>

namespace aember::auth {

namespace {

/// Public key and signature from a 32-byte seed through wolfCrypt.
struct Ed25519 {
  ed25519_key key{};
  bool ok = false;
  explicit Ed25519(const std::array<std::uint8_t, 32>& seed) {
    if (wc_ed25519_init(&key) != 0) return;
    std::array<std::uint8_t, 32> pub{};
    // The public key is derived from the private part: import the seed
    // alone, derive, then import both.
    ok = wc_ed25519_import_private_only(seed.data(), seed.size(), &key) == 0 &&
         wc_ed25519_make_public(&key, pub.data(), pub.size()) == 0 &&
         wc_ed25519_import_private_key(
             seed.data(), seed.size(), pub.data(), pub.size(), &key) == 0;
  }
  ~Ed25519() { wc_ed25519_free(&key); }
  Ed25519(const Ed25519&) = delete;
  Ed25519& operator=(const Ed25519&) = delete;
};

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
    WC_RNG rng{};
    if (wc_InitRng(&rng) != 0) return std::unexpected("no random generator");
    const int rc = wc_RNG_GenerateBlock(&rng, k.seed_.data(), k.seed_.size());
    wc_FreeRng(&rng);
    if (rc != 0) return std::unexpected("random generator failed");

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
  Ed25519 key{k.seed_};
  if (!key.ok) return std::unexpected("Ed25519 key setup failed");
  word32 len = k.public_.size();
  if (wc_ed25519_export_public(&key.key, k.public_.data(), &len) != 0) {
    return std::unexpected("cannot export the public key");
  }
  return k;
}

DeviceKey::Signature DeviceKey::Sign(
    std::span<const std::uint8_t> message) const {
  Signature sig{};
  Ed25519 key{seed_};
  word32 len = sig.size();
  if (key.ok) {
    wc_ed25519_sign_msg(
        message.data(), message.size(), sig.data(), &len, &key.key);
  }
  return sig;
}

bool DeviceKey::Verify(const PublicKey& key,
                       std::span<const std::uint8_t> message,
                       const Signature& signature) {
  ed25519_key k{};
  if (wc_ed25519_init(&k) != 0) return false;
  int verified = 0;
  const bool ok = wc_ed25519_import_public(key.data(), key.size(), &k) == 0 &&
                  wc_ed25519_verify_msg(signature.data(),
                                        signature.size(),
                                        message.data(),
                                        message.size(),
                                        &verified,
                                        &k) == 0 &&
                  verified == 1;
  wc_ed25519_free(&k);
  return ok;
}

}  // namespace aember::auth
