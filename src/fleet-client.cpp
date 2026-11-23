#include <filesystem>
#include <format>
#include <fstream>
#include <optional>

#include <unistd.h>

#include <aember-auth/base64.h>
#include <aember-auth/fleet-client.h>

namespace aember::auth {

namespace {

std::string DeviceFile(const AuthConfig& c) {
  return c.state_dir + "/device.json";
}

std::string Hostname() {
  char buf[256] = {};
  return ::gethostname(buf, sizeof(buf) - 1) == 0 ? std::string{buf} : "aember";
}

/// @p j[@p key] if it is a string.
std::optional<std::string> StringField(const nlohmann::json& j,
                                       const char* key) {
  if (!j.is_object() || !j.contains(key) || !j[key].is_string())
    return std::nullopt;
  return j[key].get<std::string>();
}

std::string Arch() {
#if defined(__x86_64__)
  return "x86_64";
#elif defined(__aarch64__)
  return "aarch64";
#elif defined(__arm__)
  return "arm";
#elif defined(__riscv)
  return "riscv64";
#else
  return "unknown";
#endif
}

}  // namespace

std::expected<AuthConfig, std::string> ParseAuthConfig(
    const nlohmann::json& j) {
  if (!j.is_object()) return std::unexpected("auth.json: not a JSON object");
  AuthConfig c;
  const auto str = [&](const char* key, std::string& out) -> bool {
    if (!j.contains(key)) return true;
    if (!j[key].is_string()) return false;
    out = j[key].get<std::string>();
    return true;
  };
  for (const auto& [key, field] : {std::pair{"server", &c.server},
                                   {"connect", &c.connect},
                                   {"ca", &c.ca},
                                   {"join_token", &c.join_token},
                                   {"name", &c.name},
                                   {"state_dir", &c.state_dir}}) {
    if (!str(key, *field)) {
      return std::unexpected(
          std::format("auth.json: '{}' must be a string", key));
    }
  }
  if (c.server.empty())
    return std::unexpected("auth.json: 'server' is missing");
  if (const auto url = ParseUrl(c.server); !url) {
    return std::unexpected("auth.json: " + url.error());
  }
  if (c.name.empty()) c.name = Hostname();
  return c;
}

std::string ChallengeMessage(std::string_view device_id,
                             std::string_view nonce) {
  return std::format("aember-auth-v1\n{}\n{}", device_id, nonce);
}

FleetClient::FleetClient(AuthConfig config, DeviceKey key, HttpClient http)
    : config_(std::move(config)), key_(std::move(key)), http_(std::move(http)) {
  std::ifstream in{DeviceFile(config_)};
  const auto j = nlohmann::json::parse(in, nullptr, false);
  device_id_ = StringField(j, "device_id").value_or("");
}

bool FleetClient::Enrolled() const {
  std::lock_guard lock{mutex_};
  return !device_id_.empty();
}

std::string FleetClient::DeviceId() const {
  std::lock_guard lock{mutex_};
  return device_id_;
}

std::expected<nlohmann::json, std::string> FleetClient::PostJson(
    std::string_view path, const nlohmann::json& body, const Headers& extra) {
  Headers headers{{"Content-Type", "application/json"}};
  headers.insert(headers.end(), extra.begin(), extra.end());
  auto r = http_.Request("POST", path, headers, body.dump());
  if (!r) return std::unexpected(r.error());
  auto j = nlohmann::json::parse(r->body, nullptr, false);
  if (r->status / 100 != 2) {
    const std::string detail =
        j.is_object() && j.contains("detail") ? j["detail"].dump() : r->body;
    return std::unexpected(std::format("{} {}: {}", path, r->status, detail));
  }
  if (j.is_discarded())
    return std::unexpected(std::format("{}: not JSON", path));
  return j;
}

std::expected<void, std::string> FleetClient::Enroll() {
  if (Enrolled()) return {};
  if (config_.join_token.empty()) {
    return std::unexpected("not enrolled and no join_token in auth.json");
  }
  const auto& pub = key_.Public();
  auto j = PostJson("/api/v1/enroll",
                    {{"join_token", config_.join_token},
                     {"public_key", Base64Encode(pub)},
                     {"name", config_.name},
                     {"info", {{"arch", Arch()}, {"hostname", Hostname()}}}});
  if (!j) return std::unexpected(j.error());
  const auto id = StringField(*j, "device_id");
  if (!id) return std::unexpected("enroll: no device_id in the answer");
  std::error_code ec;
  std::filesystem::create_directories(config_.state_dir, ec);
  const std::string tmp = DeviceFile(config_) + ".tmp";
  {
    std::ofstream out{tmp};
    out << nlohmann::json{{"device_id", *id}, {"server", config_.server}}.dump(
               2)
        << '\n';
    if (!out) return std::unexpected("cannot write " + tmp);
  }
  std::filesystem::rename(tmp, DeviceFile(config_), ec);
  if (ec) return std::unexpected("cannot write " + DeviceFile(config_));
  std::lock_guard lock{mutex_};
  device_id_ = *id;
  return {};
}

std::expected<std::string, std::string> FleetClient::Token() {
  {
    std::lock_guard lock{mutex_};
    if (device_id_.empty()) return std::unexpected("not enrolled");
    if (!token_.empty() &&
        std::chrono::steady_clock::now() + std::chrono::minutes{1} <
            token_expiry_) {
      return token_;
    }
  }
  const auto id = DeviceId();
  auto challenge = PostJson("/api/v1/auth/challenge", {{"device_id", id}});
  if (!challenge) return std::unexpected(challenge.error());
  const auto nonce = StringField(*challenge, "nonce");
  if (!nonce) return std::unexpected("challenge: no nonce");
  const auto message = ChallengeMessage(id, *nonce);
  const auto sig = key_.Sign(
      {reinterpret_cast<const std::uint8_t*>(message.data()), message.size()});
  auto token = PostJson(
      "/api/v1/auth/token",
      {{"device_id", id}, {"nonce", *nonce}, {"signature", Base64Encode(sig)}});
  if (!token) return std::unexpected(token.error());
  auto value = StringField(*token, "token");
  if (!value) return std::unexpected("token: no token in the answer");
  const int seconds = token->value("expires_in", 300);
  std::lock_guard lock{mutex_};
  token_ = std::move(*value);
  token_expiry_ =
      std::chrono::steady_clock::now() + std::chrono::seconds{seconds};
  return token_;
}

void FleetClient::ForgetToken() {
  std::lock_guard lock{mutex_};
  token_.clear();
}

std::expected<HttpResponse, std::string> FleetClient::Request(
    std::string_view method, std::string_view path, std::string_view body,
    const BodySink& sink, const HeadSink& on_head) {
  auto token = Token();
  if (!token) return std::unexpected(token.error());
  Headers headers{{"Authorization", "Bearer " + *token}};
  if (!body.empty()) headers.emplace_back("Content-Type", "application/json");
  auto r = http_.Request(method, path, headers, body, sink, on_head);
  if (r && r->status == 401) ForgetToken();
  return r;
}

}  // namespace aember::auth
