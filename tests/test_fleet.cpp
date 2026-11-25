// FleetClient against a fake fleet server (plain HTTP on 127.0.0.1): enroll,
// challenge-response login (the signature checked with the device's public
// key), authenticated requests; then the local socket (AuthServer).
#include <array>
#include <atomic>
#include <filesystem>
#include <map>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "check.h"
#include <aember-auth/base64.h>
#include <aember-auth/fleet-client.h>
#include <aember-auth/server.h>

using namespace aember::auth;
using nlohmann::json;

namespace {

/// A fleet server stand-in: one request per connection.
class FakeFleet {
 public:
  FakeFleet() {
    fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    socklen_t len = sizeof(a);
    ::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &len);
    port = ntohs(a.sin_port);
    ::listen(fd_, 8);
    thread_ = std::jthread{[this](std::stop_token st) { Loop(st); }};
  }
  ~FakeFleet() {
    thread_.request_stop();
    ::shutdown(fd_, SHUT_RDWR);
    ::close(fd_);
  }

  int port = 0;
  std::atomic<int> enrolls{0}, logins{0}, device_calls{0};
  std::string public_key;  // from the enroll request
  std::string last_auth;   // Authorization of the last device call
  std::atomic<bool> reject_tokens{false};
  std::atomic<bool> text_expiry{false};       // "expires_in" as a string
  std::atomic<bool> broken_challenge{false};  // 500, not UTF-8

 private:
  void Loop(const std::stop_token& st) {
    while (!st.stop_requested()) {
      const int c = ::accept(fd_, nullptr, nullptr);
      if (c < 0) return;
      Handle(c);
      ::close(c);
    }
  }

  void Handle(int c) {
    std::string req;
    std::array<char, 4096> buf{};
    std::size_t need = std::string::npos;
    while (true) {
      const ssize_t n = ::recv(c, buf.data(), buf.size(), 0);
      if (n <= 0) return;
      req.append(buf.data(), static_cast<std::size_t>(n));
      const auto end = req.find("\r\n\r\n");
      if (end == std::string::npos) continue;
      if (need == std::string::npos) {
        const auto cl = req.find("Content-Length: ");
        need = end + 4 + std::stoul(req.substr(cl + 16));
      }
      if (req.size() >= need) break;
    }
    const auto line_end = req.find("\r\n");
    const auto first = req.substr(0, line_end);
    const auto path = first.substr(first.find(' ') + 1,
                                   first.rfind(' ') - first.find(' ') - 1);
    const auto body = req.substr(req.find("\r\n\r\n") + 4);
    const auto auth_pos = req.find("Authorization: ");
    const std::string auth =
        auth_pos == std::string::npos
            ? ""
            : req.substr(auth_pos + 15,
                         req.find("\r\n", auth_pos) - auth_pos - 15);
    const auto j = json::parse(body, nullptr, false);

    int status = 200;
    std::string out;
    if (path == "/api/v1/enroll") {
      ++enrolls;
      if (j.value("join_token", "") != "join-123") {
        status = 403;
        out = R"({"detail":"bad join token"})";
      } else {
        public_key = j.value("public_key", "");
        out = R"({"device_id":"dev-1"})";
      }
    } else if (path == "/api/v1/auth/challenge") {
      if (broken_challenge) {
        status = 500;
        out = "\xff\xfe oops";
      } else {
        out = R"({"nonce":"n0nce"})";
      }
    } else if (path == "/api/v1/auth/token") {
      const auto pub = Base64Decode(public_key);
      const auto sig = Base64Decode(j.value("signature", ""));
      const auto msg =
          ChallengeMessage(j.value("device_id", ""), j.value("nonce", ""));
      DeviceKey::PublicKey pk{};
      DeviceKey::Signature s{};
      const bool ok = pub && sig && pub->size() == 32 && sig->size() == 64;
      if (ok) {
        std::copy(pub->begin(), pub->end(), pk.begin());
        std::copy(sig->begin(), sig->end(), s.begin());
      }
      if (!ok ||
          !DeviceKey::Verify(
              pk,
              {reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()},
              s)) {
        status = 401;
        out = R"({"detail":"bad signature"})";
      } else {
        ++logins;
        out = R"({"token":"tok-)" + std::to_string(logins.load()) +
              (text_expiry ? R"(","expires_in":"600"})"
                           : R"(","expires_in":600})");
      }
    } else if (path.starts_with("/api/v1/device/")) {
      ++device_calls;
      last_auth = auth;
      if (reject_tokens) {
        status = 401;
        out = R"({"detail":"expired"})";
      } else {
        out = R"({"containers":[],"echo":)" +
              (body.empty() ? std::string{"null"} : body) + "}";
      }
    } else {
      status = 404;
      out = "{}";
    }
    const auto resp =
        "HTTP/1.1 " + std::to_string(status) +
        " X\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(out.size()) + "\r\n\r\n" + out;
    ::send(c, resp.data(), resp.size(), MSG_NOSIGNAL);
  }

  int fd_ = -1;
  std::jthread thread_;
};

/// One request over the local socket: the head line and the rest.
std::pair<json, std::string> Ask(const std::string& sock, const json& req) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  sock.copy(a.sun_path, sizeof(a.sun_path) - 1);
  for (int i = 0; i < 50; ++i) {
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) break;
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
  }
  const auto line = req.dump() + "\n";
  ::send(fd, line.data(), line.size(), MSG_NOSIGNAL);
  std::string all;
  std::array<char, 4096> buf{};
  ssize_t n;
  while ((n = ::recv(fd, buf.data(), buf.size(), 0)) > 0) {
    all.append(buf.data(), static_cast<std::size_t>(n));
  }
  ::close(fd);
  const auto nl = all.find('\n');
  return {json::parse(all.substr(0, nl), nullptr, false),
          nl == std::string::npos ? "" : all.substr(nl + 1)};
}

}  // namespace

int main() {
  char dir[] = "/tmp/aember-auth-fleet-XXXXXX";
  if (::mkdtemp(dir) == nullptr) return 1;
  FakeFleet fleet;

  // Config parsing.
  CHECK(!ParseAuthConfig(json::array()).has_value());
  CHECK(!ParseAuthConfig(json{{"join_token", "x"}}).has_value());  // no server
  CHECK(!ParseAuthConfig(json{{"server", "ftp://x"}}).has_value());
  CHECK(!ParseAuthConfig(json{{"server", "https://x"}, {"ca", 3}}).has_value());

  auto config = ParseAuthConfig(
      json{{"server", "http://127.0.0.1:" + std::to_string(fleet.port)},
           {"join_token", "join-123"},
           {"name", "test-device"},
           {"state_dir", std::string{dir}}});
  CHECK(config.has_value());
  if (!config) return Failures();
  auto key = DeviceKey::LoadOrCreate(config->state_dir + "/device.key");
  CHECK(key.has_value());

  FleetClient client{*config, *key, HttpClient{*ParseUrl(config->server), ""}};
  CHECK(!client.Enrolled());
  CHECK(!client.Token().has_value());  // not enrolled yet
  CHECK(client.Enroll().has_value());
  CHECK(client.Enrolled());
  CHECK_EQ(client.DeviceId(), std::string{"dev-1"});
  CHECK(client.Enroll().has_value());  // second time: nothing to do
  CHECK_EQ(fleet.enrolls.load(), 1);
  CHECK_EQ(fleet.public_key, Base64Encode(key->Public()));

  auto token = client.Token();
  CHECK(token.has_value() && *token == "tok-1");
  CHECK(client.Token().has_value());  // cached
  CHECK_EQ(fleet.logins.load(), 1);

  auto r = client.Request("POST", "/api/v1/device/status", R"({"x":1})");
  CHECK(r.has_value() && r->status == 200);
  CHECK_EQ(fleet.last_auth, std::string{"Bearer tok-1"});
  if (r) CHECK(json::parse(r->body)["echo"]["x"] == 1);

  // A 401 drops the token: the next request logs in again.
  fleet.reject_tokens = true;
  r = client.Request("GET", "/api/v1/device/desired", "");
  CHECK(r.has_value() && r->status == 401);
  fleet.reject_tokens = false;
  r = client.Request("GET", "/api/v1/device/desired", "");
  CHECK(r.has_value() && r->status == 200);
  CHECK_EQ(fleet.logins.load(), 2);

  // Regression: an "expires_in" that wasn't a number threw out of Token()
  // and ended aember-auth (found by fuzz_fleet_responses).
  fleet.text_expiry = true;
  client.ForgetToken();
  token = client.Token();
  CHECK(token.has_value() && *token == "tok-3");
  fleet.text_expiry = false;

  // A restart keeps the enrollment (device.json).
  FleetClient restarted{
      *config, *key, HttpClient{*ParseUrl(config->server), ""}};
  CHECK(restarted.Enrolled());
  CHECK_EQ(restarted.DeviceId(), std::string{"dev-1"});

  // A wrong join token is refused.
  {
    const std::string other = std::string{dir} + "/other";
    auto c2 = *config;
    c2.state_dir = other;
    c2.join_token = "wrong";
    FleetClient refused{c2,
                        *DeviceKey::LoadOrCreate(other + "/device.key"),
                        HttpClient{*ParseUrl(config->server), ""}};
    auto e = refused.Enroll();
    CHECK(!e.has_value());
    if (!e) CHECK(e.error().find("403") != std::string::npos);
  }

  // The local socket.
  const std::string sock = std::string{dir} + "/run/auth.sock";
  AuthServer server{client, sock};
  CHECK(server.Open().has_value());
  std::jthread serving{[&](std::stop_token st) { server.Serve(st); }};

  auto [status, rest] = Ask(sock, {{"op", "status"}});
  CHECK(status["ok"] == true && status["enrolled"] == true);
  CHECK_EQ(status["device_id"].get<std::string>(), std::string{"dev-1"});

  auto [head, body] = Ask(sock,
                          {{"op", "request"},
                           {"method", "POST"},
                           {"path", "/api/v1/device/status"},
                           {"body", {{"state", "ok"}}}});
  CHECK(head["ok"] == true && head["status"] == 200);
  CHECK_EQ(head["content_type"].get<std::string>(),
           std::string{"application/json"});
  CHECK(json::parse(body, nullptr, false)["echo"]["state"] == "ok");

  for (const auto& bad :
       {json{{"op", "request"}, {"path", "/api/v1/enroll"}},
        json{{"op", "request"}, {"path", "/api/v1/device/../enroll"}},
        json{{"op", "request"},
             {"method", "DELETE"},
             {"path", "/api/v1/device/x"}},
        json{{"op", "nope"}},
        json{{"no", "op"}},
        // Regression: a method or path that wasn't a string threw out of
        // the connection's thread and ended aember-auth (found by
        // fuzz_socket).
        json{{"op", "request"}, {"method", 1}, {"path", "/api/v1/device/x"}},
        json{{"op", "request"}, {"path", json::array()}}}) {
    auto [h, b] = Ask(sock, bad);
    CHECK(h["ok"] == false);
    CHECK(h.contains("error"));
  }

  // Regression: an error text with the fleet server's raw bytes (not
  // UTF-8) threw in json::dump() and ended aember-auth (found by
  // fuzz_fleet_responses). Now the client gets the error, U+FFFD inside.
  client.ForgetToken();
  fleet.broken_challenge = true;
  {
    auto [h, b] = Ask(sock, {{"op", "request"}, {"path", "/api/v1/device/x"}});
    CHECK(h["ok"] == false);
    CHECK(h.value("error", "").find("500") != std::string::npos);
    CHECK(h.value("error", "").find("\xef\xbf\xbd") != std::string::npos);
  }
  fleet.broken_challenge = false;
  serving.request_stop();
  serving.join();
  std::filesystem::remove_all(dir);
  return Failures();
}
