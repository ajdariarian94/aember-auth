// The local socket (/run/aember-auth/auth.sock): any bytes from a local
// client into HandleConnection. The device isn't enrolled, so a valid
// request ends at "not enrolled" without network. The answer must start
// with one JSON object line.
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>

#include <sys/socket.h>
#include <unistd.h>

#include <aember-auth/server.h>

namespace {

aember::auth::FleetClient& Fleet() {
  using namespace aember::auth;
  static FleetClient* fleet = [] {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("aember-auth-fuzz-socket-" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    AuthConfig config;
    config.server = "http://127.0.0.1:9";
    config.state_dir = dir.string();
    auto key = DeviceKey::LoadOrCreate((dir / "device.key").string());
    return new FleetClient{config, *key, HttpClient{{false, "127.0.0.1", 9}, ""}};
  }();
  return *fleet;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  int fds[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) return 0;
  // Fits the socket buffer; then the client stops writing.
  if (size > 0 && ::send(fds[0], data, size, MSG_NOSIGNAL) < 0) std::abort();
  ::shutdown(fds[0], SHUT_WR);
  aember::auth::HandleConnection(fds[1], Fleet());  // closes fds[1]
  std::string answer;
  char buf[4096];
  ssize_t n;
  while ((n = ::recv(fds[0], buf, sizeof(buf), 0)) > 0) answer.append(buf, n);
  ::close(fds[0]);
  const auto nl = answer.find('\n');
  if (nl == std::string::npos) std::abort();  // always an answer line
  const auto j = nlohmann::json::parse(answer.substr(0, nl), nullptr, false);
  if (!j.is_object() || !j.contains("ok")) std::abort();
  return 0;
}
