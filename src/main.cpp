/**
 * @file main.cpp
 * @brief aember-auth: the device's identity towards aember-fleet.
 *
 *   aember-auth [--config /etc/aember-auth/auth.json]
 *               [--socket /run/aember-auth/auth.sock]
 */
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <string_view>
#include <thread>

#include <aember-auth/server.h>

namespace {

std::atomic<bool> g_stop{false};

void OnSignal(int) {
  g_stop = true;
}

void Sleep(std::chrono::seconds s) {
  const auto until = std::chrono::steady_clock::now() + s;
  while (!g_stop && std::chrono::steady_clock::now() < until) {
    std::this_thread::sleep_for(std::chrono::milliseconds{200});
  }
}

}  // namespace

int main(int argc, char** argv) {
  using namespace aember::auth;
  std::string config_path = "/etc/aember-auth/auth.json";
  std::string socket_path = "/run/aember-auth/auth.sock";
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    if (a == "--config" && i + 1 < argc) {
      config_path = argv[++i];
    } else if (a == "--socket" && i + 1 < argc) {
      socket_path = argv[++i];
    } else {
      std::cerr << "usage: aember-auth [--config FILE] [--socket PATH]\n";
      return 2;
    }
  }
  std::signal(SIGTERM, OnSignal);
  std::signal(SIGINT, OnSignal);
  std::signal(SIGPIPE, SIG_IGN);

  std::ifstream in{config_path};
  const auto j = nlohmann::json::parse(in, nullptr, false);
  auto config = ParseAuthConfig(j.is_discarded() ? nlohmann::json{} : j);
  if (!config) {
    std::cerr << "aember-auth: " << config_path << ": " << config.error()
              << '\n';
    return 1;
  }
  auto key = DeviceKey::LoadOrCreate(config->state_dir + "/device.key");
  if (!key) {
    std::cerr << "aember-auth: " << key.error() << '\n';
    return 1;
  }
  const auto url = ParseUrl(config->server);
  FleetClient fleet{
      *config, *key, HttpClient{*url, config->ca, config->connect}};
  AuthServer server{fleet, socket_path};
  if (auto r = server.Open(); !r) {
    std::cerr << "aember-auth: " << r.error() << '\n';
    return 1;
  }
  std::jthread serving{[&](std::stop_token st) { server.Serve(st); }};
  std::cerr << "aember-auth: serving " << socket_path << ", fleet "
            << config->server << '\n';

  // Enroll (once per device), then log in once to show it works; tokens
  // are refreshed on demand afterwards.
  std::chrono::seconds backoff{5};
  bool logged_in = false;
  while (!g_stop && !logged_in) {
    if (auto r = fleet.Enroll(); !r) {
      std::cerr << "aember-auth: enroll: " << r.error() << " (retry in "
                << backoff.count() << " s)\n";
    } else if (auto t = fleet.Token(); !t) {
      std::cerr << "aember-auth: login: " << t.error() << " (retry in "
                << backoff.count() << " s)\n";
    } else {
      std::cerr << "aember-auth: device " << fleet.DeviceId() << " logged in\n";
      logged_in = true;
      break;
    }
    Sleep(backoff);
    backoff = std::min(backoff * 2, std::chrono::seconds{300});
  }
  while (!g_stop) Sleep(std::chrono::seconds{3600});
  std::cerr << "aember-auth: stopping\n";
  return 0;
}
