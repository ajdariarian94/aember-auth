/**
 * @file server.h
 * @brief aember-auth's local socket (default /run/aember-auth/auth.sock):
 *        services on the device (the aember-fleet agent) reach the fleet
 *        server through it without ever holding the device key or a TLS
 *        stack. One JSON line per connection:
 *
 *   {"op": "status"}  -> {"ok": true, "enrolled": bool, "device_id": "...",
 *                         "server": "..."}
 *   {"op": "request", "method": "GET"|"POST"|"PUT",
 *    "path": "/api/v1/device/...", "body": <string or JSON>}
 *       -> {"ok": true, "status": 200, "content_type": "..."}  (one line)
 *          then the response body until the connection closes
 *
 * Errors: {"ok": false, "error": "..."}. Only /api/v1/device/ paths are
 * forwarded: a local client gets the device's rights, nothing else.
 */
#pragma once

#include <atomic>
#include <expected>
#include <stop_token>
#include <string>

#include <aember-auth/fleet-client.h>

namespace aember::auth {

/// Answer one client connection on @p fd (closes it).
void HandleConnection(int fd, FleetClient& fleet);

class AuthServer {
 public:
  AuthServer(FleetClient& fleet, std::string socket_path);
  ~AuthServer();
  AuthServer(const AuthServer&) = delete;
  AuthServer& operator=(const AuthServer&) = delete;

  /// Create the socket (its directory too); a stale socket is replaced.
  std::expected<void, std::string> Open();
  /// Accept connections until @p stop (one thread each, at most 8 at once).
  void Serve(const std::stop_token& stop);

 private:
  FleetClient& fleet_;
  std::string path_;
  int fd_ = -1;
  std::atomic<int> active_{0};
};

}  // namespace aember::auth
