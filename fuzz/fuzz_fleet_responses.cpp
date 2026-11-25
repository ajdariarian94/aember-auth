// What the fleet server answers: a fake server on 127.0.0.1 sends fuzzed
// responses to the login (challenge, token) and to a forwarded request,
// for an enrolled device, through HandleConnection like a local client's
// request. The client must always get one JSON answer line.
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <aember-auth/server.h>

namespace {

struct Setup {
  std::filesystem::path dir;
  aember::auth::DeviceKey key;
  int listen_fd = -1;
  int port = 0;
};

Setup& Get() {
  static Setup* s = [] {
    using namespace aember::auth;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("aember-auth-fuzz-fleet-" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    std::ofstream{dir / "device.json"} << R"({"device_id":"d-1"})";
    auto key = DeviceKey::LoadOrCreate((dir / "device.key").string());
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(a);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
        ::listen(fd, 16) != 0 ||
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
      std::abort();
    }
    return new Setup{dir, *key, fd, ntohs(a.sin_port)};
  }();
  return *s;
}

/// Reads one request (headers + Content-Length body), sends @p answer.
void Serve(int fd, const std::string& answer) {
  std::string in;
  char buf[4096];
  while (true) {
    const auto end = in.find("\r\n\r\n");
    if (end != std::string::npos) {
      std::size_t length = 0;
      if (const auto cl = in.find("Content-Length: "); cl < end) {
        length = std::stoul(in.substr(cl + 16));
      }
      if (in.size() >= end + 4 + length) break;
    }
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    in.append(buf, static_cast<std::size_t>(n));
  }
  std::string_view out{answer};
  while (!out.empty()) {
    const ssize_t n = ::send(fd, out.data(), out.size(), MSG_NOSIGNAL);
    if (n <= 0) break;
    out.remove_prefix(static_cast<std::size_t>(n));
  }
  ::close(fd);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace aember::auth;
  auto& s = Get();
  FuzzedDataProvider fdp{data, size};
  std::vector<std::string> answers;  // challenge, token, the request
  for (int i = 0; i < 3; ++i)
    answers.push_back(fdp.ConsumeRandomLengthString());
  const bool post = fdp.ConsumeBool();

  std::atomic<bool> done{false};
  std::thread server{[&] {
    std::size_t next = 0;
    while (!done) {
      pollfd p{s.listen_fd, POLLIN, 0};
      if (::poll(&p, 1, 5) <= 0) continue;
      const int fd = ::accept4(s.listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
      if (fd < 0) continue;
      Serve(fd, next < answers.size() ? answers[next] : std::string{});
      ++next;
    }
  }};

  AuthConfig config;
  config.server = "http://127.0.0.1:" + std::to_string(s.port);
  config.state_dir = s.dir.string();
  FleetClient fleet{
      config, s.key, HttpClient{{false, "127.0.0.1", s.port}, ""}};

  int fds[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
    std::abort();
  const std::string line =
      post
          ? R"({"op":"request","method":"POST","path":"/api/v1/device/status","body":{"a":1}})"
            "\n"
          : R"({"op":"request","method":"GET","path":"/api/v1/device/desired"})"
            "\n";
  ::send(fds[0], line.data(), line.size(), MSG_NOSIGNAL);
  ::shutdown(fds[0], SHUT_WR);
  HandleConnection(fds[1], fleet);  // closes fds[1]
  done = true;
  server.join();

  std::string answer;
  char buf[4096];
  ssize_t n;
  while ((n = ::recv(fds[0], buf, sizeof(buf), 0)) > 0) answer.append(buf, n);
  ::close(fds[0]);
  const auto nl = answer.find('\n');
  if (nl == std::string::npos) std::abort();
  const auto j = nlohmann::json::parse(answer.substr(0, nl), nullptr, false);
  if (!j.is_object() || !j.contains("ok")) std::abort();
  return 0;
}
