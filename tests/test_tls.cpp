// HttpClient over TLS against `openssl s_server`, for whichever backend the
// build uses (src/tls-*.cpp): a good certificate is accepted, a wrong name
// or another CA is refused. Skipped (passes) when no openssl binary is found.
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <string>
#include <thread>

#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/tls.h"
#include "check.h"
#include <aember-auth/http.h>

using namespace aember::auth;
namespace fs = std::filesystem;

namespace {

bool Run(const std::string& command) {
  return std::system((command + " >/dev/null 2>&1").c_str()) == 0;
}

/// A free TCP port on 127.0.0.1 (bound, read, released).
int FreePort() {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
  socklen_t len = sizeof(a);
  ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
  ::close(fd);
  return ntohs(a.sin_port);
}

bool Listening(int port) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(static_cast<std::uint16_t>(port));
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const bool ok =
      ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
  ::close(fd);
  return ok;
}

/// A CA (P-256, like aember-fleet's) in @p dir as <name>.pem/.key.
bool MakeCa(const fs::path& dir, const std::string& name) {
  return Run(std::format(
      "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "
      "-days 1 -subj /CN={0} -keyout {1}/{0}.key -out {1}/{0}.pem "
      "-addext basicConstraints=critical,CA:TRUE "
      "-addext keyUsage=critical,keyCertSign,cRLSign",
      name, dir.string()));
}

}  // namespace

int main() {
  std::cerr << "TLS backend: " << TlsBackend() << "\n";
  if (!Run("openssl version")) {
    std::cerr << "skipped: no openssl binary\n";
    return Failures();
  }
  const fs::path dir = fs::temp_directory_path() /
                       std::format("aember-auth-tls-{}", ::getpid());
  fs::create_directories(dir);
  const std::string d = dir.string();
  CHECK(MakeCa(dir, "ca"));
  CHECK(MakeCa(dir, "other-ca"));
  // The server's certificate: for fleet.test, from "ca".
  CHECK(Run(std::format(
      "openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "
      "-subj /CN=fleet.test -keyout {0}/srv.key -out {0}/srv.csr", d)));
  {
    std::FILE* ext = std::fopen((dir / "ext.cnf").c_str(), "w");
    std::fputs("subjectAltName=DNS:fleet.test\n"
               "extendedKeyUsage=serverAuth\n", ext);
    std::fclose(ext);
  }
  CHECK(Run(std::format(
      "openssl x509 -req -in {0}/srv.csr -CA {0}/ca.pem -CAkey {0}/ca.key "
      "-CAcreateserial -days 1 -extfile {0}/ext.cnf -out {0}/srv.pem", d)));

  const int port = FreePort();
  const pid_t server = ::fork();
  if (server == 0) {
    const std::string accept = std::format("127.0.0.1:{}", port);
    const std::string cert = d + "/srv.pem";
    const std::string key = d + "/srv.key";
    ::freopen("/dev/null", "w", stdout);
    ::freopen("/dev/null", "w", stderr);
    ::execlp("openssl", "openssl", "s_server", "-quiet", "-www", "-accept",
             accept.c_str(), "-cert", cert.c_str(), "-key", key.c_str(),
             static_cast<char*>(nullptr));
    ::_exit(127);
  }
  bool up = false;
  for (int i = 0; i < 100 && !(up = Listening(port)); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  CHECK(up);

  {  // The pinned CA, the right name (connecting to an address): accepted.
    HttpClient c{Url{true, "fleet.test", port}, d + "/ca.pem", "127.0.0.1"};
    auto r = c.Request("GET", "/", {}, "");
    CHECK(r.has_value());
    if (r) CHECK_EQ(r->status, 200);
    if (!r) std::cerr << r.error() << "\n";
  }
  {  // Another name than the certificate's: refused.
    HttpClient c{Url{true, "evil.test", port}, d + "/ca.pem", "127.0.0.1"};
    auto r = c.Request("GET", "/", {}, "");
    CHECK(!r.has_value());
    if (!r) CHECK(r.error().find("TLS handshake") != std::string::npos);
  }
  {  // Another CA than the one that signed it: refused.
    HttpClient c{Url{true, "fleet.test", port}, d + "/other-ca.pem",
                 "127.0.0.1"};
    CHECK(!c.Request("GET", "/", {}, "").has_value());
  }
  {  // A CA file that isn't there: an error, not a crash.
    HttpClient c{Url{true, "fleet.test", port}, d + "/missing.pem",
                 "127.0.0.1"};
    auto r = c.Request("GET", "/", {}, "");
    CHECK(!r.has_value());
    if (!r) CHECK(r.error().find("CA") != std::string::npos);
  }

  ::kill(server, SIGTERM);
  ::waitpid(server, nullptr, 0);
  fs::remove_all(dir);
  return Failures();
}
