/**
 * @file device-key.h
 * @brief The device's Ed25519 key: made on first start, kept in the state
 *        directory (0600) and never sent anywhere. The fleet server knows
 *        the public half from enrollment and checks the challenge signatures
 *        made with it.
 */
#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace aember::auth {

class DeviceKey {
 public:
  using PublicKey = std::array<std::uint8_t, 32>;
  using Signature = std::array<std::uint8_t, 64>;

  /// The key in @p path (32-byte seed, base64), or a new one written there
  /// with mode 0600 (directory created 0700).
  static std::expected<DeviceKey, std::string> LoadOrCreate(
      const std::string& path);

  [[nodiscard]] const PublicKey& Public() const { return public_; }
  [[nodiscard]] Signature Sign(std::span<const std::uint8_t> message) const;

  /// Check @p signature over @p message with @p key (tests, and the fleet
  /// agent's release signatures use the same scheme).
  static bool Verify(const PublicKey& key,
                     std::span<const std::uint8_t> message,
                     const Signature& signature);

 private:
  std::array<std::uint8_t, 32> seed_{};
  PublicKey public_{};
};

}  // namespace aember::auth
