// The state directory's files, which a crash or a full disk can leave
// broken: device.key (DeviceKey::LoadOrCreate) and device.json (read by
// FleetClient's constructor). First byte: which file.
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include <unistd.h>

#include <aember-auth/fleet-client.h>

namespace {

const std::filesystem::path& Dir() {
  static const auto dir = [] {
    auto d = std::filesystem::temp_directory_path() /
             ("aember-auth-fuzz-" + std::to_string(::getpid()));
    std::filesystem::create_directories(d);
    return d;
  }();
  return dir;
}

void Write(const std::filesystem::path& path, const std::uint8_t* data,
           std::size_t size) {
  std::ofstream out{path, std::ios::binary | std::ios::trunc};
  out.write(reinterpret_cast<const char*>(data),
            static_cast<std::streamsize>(size));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace aember::auth;
  if (size < 1) return 0;
  const auto key_file = Dir() / "device.key";
  if (data[0] & 1) {
    Write(key_file, data + 1, size - 1);
    const auto key = DeviceKey::LoadOrCreate(key_file.string());
    if (key) {  // a loaded key signs what it verifies
      const std::uint8_t msg[] = {'m'};
      if (!DeviceKey::Verify(key->Public(), msg, key->Sign(msg))) std::abort();
    }
    return 0;
  }
  static const auto key = [&] {
    std::filesystem::remove(Dir() / "fixed.key");
    return *DeviceKey::LoadOrCreate((Dir() / "fixed.key").string());
  }();
  Write(Dir() / "device.json", data + 1, size - 1);
  AuthConfig config;
  config.server = "http://127.0.0.1:9";
  config.state_dir = Dir().string();
  FleetClient fleet{config, key, HttpClient{{false, "127.0.0.1", 9}, ""}};
  if (fleet.Enrolled() == fleet.DeviceId().empty()) std::abort();
  return 0;
}
