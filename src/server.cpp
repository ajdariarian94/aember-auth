#include <array>
#include <filesystem>
#include <format>
#include <iostream>
#include <optional>
#include <thread>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <aember-auth/server.h>

namespace aember::auth {

namespace {

bool SendAll(int fd, std::string_view data) {
  while (!data.empty()) {
    const ssize_t n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
    if (n <= 0) return false;
    data.remove_prefix(static_cast<std::size_t>(n));
  }
  return true;
}

void SendLine(int fd, const nlohmann::json& j) {
  SendAll(fd, j.dump() + "\n");
}

void SendError(int fd, std::string message) {
  SendLine(fd, {{"ok", false}, {"error", std::move(message)}});
}

/// The request line (up to 64 KB, a short timeout).
std::optional<std::string> ReadLine(int fd) {
  std::string line;
  std::array<char, 4096> buf{};
  while (line.size() < 64 * 1024) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return std::nullopt;
    line.append(buf.data(), static_cast<std::size_t>(n));
    if (const auto nl = line.find('\n'); nl != std::string::npos) {
      line.resize(nl);
      return line;
    }
  }
  return std::nullopt;
}

}  // namespace

void HandleConnection(int fd, FleetClient& fleet) {
  timeval tv{10, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  const auto line = ReadLine(fd);
  const auto req = line ? nlohmann::json::parse(*line, nullptr, false)
                        : nlohmann::json(nlohmann::json::value_t::discarded);
  if (!req.is_object() || !req.contains("op") || !req["op"].is_string()) {
    SendError(fd, "want one JSON line with \"op\"");
    ::close(fd);
    return;
  }
  const auto op = req["op"].get<std::string>();
  if (op == "status") {
    SendLine(fd,
             {{"ok", true},
              {"enrolled", fleet.Enrolled()},
              {"device_id", fleet.DeviceId()},
              {"server", fleet.config().server}});
  } else if (op == "request") {
    const auto method = req.value("method", std::string{"GET"});
    const auto path = req.value("path", std::string{});
    std::string body;
    if (req.contains("body")) {
      body = req["body"].is_string() ? req["body"].get<std::string>()
                                     : req["body"].dump();
    }
    if (method != "GET" && method != "POST" && method != "PUT") {
      SendError(fd, "method must be GET, POST or PUT");
    } else if (!path.starts_with("/api/v1/device/") ||
               path.find("..") != std::string::npos) {
      SendError(fd, "only /api/v1/device/ paths are forwarded");
    } else {
      bool head_sent = false;
      auto r = fleet.Request(
          method,
          path,
          body,
          [fd](std::string_view chunk) { return SendAll(fd, chunk); },
          [&](const HttpResponse& head) {
            const auto ct = head.headers.find("content-type");
            SendLine(
                fd,
                {{"ok", true},
                 {"status", head.status},
                 {"content_type", ct == head.headers.end() ? "" : ct->second}});
            head_sent = true;
          });
      if (!r && !head_sent) SendError(fd, r.error());
      if (!r)
        std::cerr << "aember-auth: " << method << " " << path << ": "
                  << r.error() << '\n';
    }
  } else {
    SendError(fd, std::format("unknown op '{}'", op));
  }
  ::close(fd);
}

AuthServer::AuthServer(FleetClient& fleet, std::string socket_path)
    : fleet_(fleet), path_(std::move(socket_path)) {}

AuthServer::~AuthServer() {
  if (fd_ >= 0) {
    ::close(fd_);
    ::unlink(path_.c_str());
  }
}

std::expected<void, std::string> AuthServer::Open() {
  sockaddr_un addr{};
  if (path_.size() >= sizeof(addr.sun_path))
    return std::unexpected("socket path too long");
  std::error_code ec;
  std::filesystem::create_directories(
      std::filesystem::path{path_}.parent_path(), ec);
  ::unlink(path_.c_str());
  fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd_ < 0) return std::unexpected("socket() failed");
  addr.sun_family = AF_UNIX;
  path_.copy(addr.sun_path, sizeof(addr.sun_path) - 1);
  if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
      ::listen(fd_, 16) != 0) {
    return std::unexpected(std::format("cannot listen on {}", path_));
  }
  return {};
}

void AuthServer::Serve(const std::stop_token& stop) {
  while (!stop.stop_requested()) {
    pollfd p{fd_, POLLIN, 0};
    if (::poll(&p, 1, 500) <= 0) continue;
    const int client = ::accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (client < 0) continue;
    if (active_ >= 8) {
      SendError(client, "busy");
      ::close(client);
      continue;
    }
    ++active_;
    std::thread{[this, client] {
      HandleConnection(client, fleet_);
      --active_;
    }}.detach();
  }
  while (active_ > 0)
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
}

}  // namespace aember::auth
