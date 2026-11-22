/**
 * @file fleet-client.h
 * @brief The device's side of the aember-fleet API: enrollment (once, with
 *        the join token) and challenge-response login for short-lived
 *        tokens, then authenticated requests on behalf of local services.
 *
 *   POST /api/v1/enroll         {join_token, public_key, name, info}
 *                                -> {device_id}
 *   POST /api/v1/auth/challenge {device_id} -> {nonce}
 *   POST /api/v1/auth/token     {device_id, nonce, signature}
 *                                -> {token, expires_in}
 *
 * The signature is Ed25519 over "aember-auth-v1\n<device_id>\n<nonce>".
 */
#pragma once

#include <nlohmann/json.hpp>

#include <chrono>
#include <expected>
#include <mutex>
#include <string>

#include <aember-auth/device-key.h>
#include <aember-auth/http.h>

namespace aember::auth {

struct AuthConfig {
  std::string server;   ///< https://name[:port]
  std::string connect;  ///< optional: address to connect to instead
  std::string ca = "/etc/aember-auth/ca.pem";
  std::string join_token;  ///< only needed until the device is enrolled
  std::string name;        ///< shown in the fleet; default: hostname
  std::string state_dir = "/var/lib/aember-auth";
};

/// Parse auth.json; errors name the missing or bad field.
std::expected<AuthConfig, std::string> ParseAuthConfig(const nlohmann::json& j);

/// What gets signed for a challenge.
std::string ChallengeMessage(std::string_view device_id,
                             std::string_view nonce);

class FleetClient {
 public:
  FleetClient(AuthConfig config, DeviceKey key, HttpClient http);

  [[nodiscard]] bool Enrolled() const;
  [[nodiscard]] std::string DeviceId() const;
  [[nodiscard]] const AuthConfig& config() const { return config_; }

  /// Enroll unless state_dir/device.json already has a device id.
  std::expected<void, std::string> Enroll();

  /// A token valid for at least another minute (logs in when needed).
  std::expected<std::string, std::string> Token();
  void ForgetToken();

  /// An authenticated request; a 401 drops the cached token.
  std::expected<HttpResponse, std::string> Request(
      std::string_view method, std::string_view path, std::string_view body,
      const BodySink& sink = {}, const HeadSink& on_head = {});

 private:
  std::expected<nlohmann::json, std::string> PostJson(
      std::string_view path, const nlohmann::json& body,
      const Headers& extra = {});

  AuthConfig config_;
  DeviceKey key_;
  HttpClient http_;
  mutable std::mutex mutex_;
  std::string device_id_;
  std::string token_;
  std::chrono::steady_clock::time_point token_expiry_{};
};

}  // namespace aember::auth
