// TLS through mbedTLS (Apache-2.0). Builds against mbedTLS 2.28 (Ubuntu
// 24.04's, the host tests) and 3.6 (meta-networking, the SDK).
#include <cerrno>
#include <format>
#include <mutex>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <sys/socket.h>
#if MBEDTLS_VERSION_MAJOR >= 3
#include <psa/crypto.h>
#endif

#include "tls.h"

namespace aember::auth {

namespace {

std::string ErrorText(int rc) {
  char text[128] = {};
  mbedtls_strerror(rc, text, sizeof(text));
  return text;
}

// The socket as mbedTLS's BIO: a blocking fd, EINTR retried.
int Send(void* ctx, const unsigned char* buf, std::size_t len) {
  const int fd = *static_cast<int*>(ctx);
  for (;;) {
    const ssize_t n = ::send(fd, buf, len, MSG_NOSIGNAL);
    if (n >= 0) return static_cast<int>(n);
    if (errno != EINTR) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
}

int Recv(void* ctx, unsigned char* buf, std::size_t len) {
  const int fd = *static_cast<int*>(ctx);
  for (;;) {
    const ssize_t n = ::recv(fd, buf, len, 0);
    if (n >= 0) return static_cast<int>(n);
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return MBEDTLS_ERR_SSL_TIMEOUT;  // SO_RCVTIMEO ran out
    }
    if (errno != EINTR) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
}

/// Everything one connection needs, freed in reverse order.
class MbedTlsStream : public TlsStream {
 public:
  explicit MbedTlsStream(int fd) : fd_(fd) {
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&conf_);
    mbedtls_x509_crt_init(&ca_);
    mbedtls_ctr_drbg_init(&drbg_);
    mbedtls_entropy_init(&entropy_);
  }
  ~MbedTlsStream() override {
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&conf_);
    mbedtls_x509_crt_free(&ca_);
    mbedtls_ctr_drbg_free(&drbg_);
    mbedtls_entropy_free(&entropy_);
  }
  MbedTlsStream(const MbedTlsStream&) = delete;
  MbedTlsStream& operator=(const MbedTlsStream&) = delete;

  std::expected<void, std::string> Handshake(const std::string& host,
                                             const std::string& ca_file) {
    static constexpr unsigned char kPersonal[] = "aember-auth";
    int rc = mbedtls_ctr_drbg_seed(&drbg_, mbedtls_entropy_func, &entropy_,
                                   kPersonal, sizeof(kPersonal) - 1);
    if (rc != 0) return Fail("random generator", rc);
    rc = mbedtls_x509_crt_parse_file(&ca_, ca_file.c_str());
    if (rc != 0) {
      return std::unexpected(
          std::format("cannot load CA {}: {}", ca_file, ErrorText(rc)));
    }
    rc = mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) return Fail("TLS setup", rc);
    mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf_, &ca_, nullptr);
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &drbg_);
    rc = mbedtls_ssl_setup(&ssl_, &conf_);
    if (rc != 0) return Fail("TLS setup", rc);
    // SNI and the name the certificate must carry.
    rc = mbedtls_ssl_set_hostname(&ssl_, host.c_str());
    if (rc != 0) return Fail("TLS setup", rc);
    mbedtls_ssl_set_bio(&ssl_, &fd_, Send, Recv, nullptr);
    while ((rc = mbedtls_ssl_handshake(&ssl_)) != 0) {
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }
      std::string why = ErrorText(rc);
      if (const auto flags = mbedtls_ssl_get_verify_result(&ssl_);
          flags != 0 && flags != static_cast<std::uint32_t>(-1)) {
        char info[256] = {};
        mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
        why = info;
        while (!why.empty() && why.back() == '\n') why.pop_back();
      }
      return std::unexpected(std::format("TLS handshake with {}: {}", host, why));
    }
    return {};
  }

  ssize_t Read(char* buf, std::size_t n) override {
    for (;;) {
      const int r = mbedtls_ssl_read(
          &ssl_, reinterpret_cast<unsigned char*>(buf), n);
      if (r > 0) return r;
      if (r == 0 || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }
#if defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
      // TLS 1.3: a ticket after the handshake, not data.
      if (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
#endif
      return -1;
    }
  }

  bool WriteAll(std::string_view data) override {
    while (!data.empty()) {
      const int r = mbedtls_ssl_write(
          &ssl_, reinterpret_cast<const unsigned char*>(data.data()),
          data.size());
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }
      if (r <= 0) return false;
      data.remove_prefix(static_cast<std::size_t>(r));
    }
    return true;
  }

 private:
  static std::unexpected<std::string> Fail(std::string_view what, int rc) {
    return std::unexpected(std::format("{} failed: {}", what, ErrorText(rc)));
  }

  int fd_;
  mbedtls_ssl_context ssl_;
  mbedtls_ssl_config conf_;
  mbedtls_x509_crt ca_;
  mbedtls_ctr_drbg_context drbg_;
  mbedtls_entropy_context entropy_;
};

}  // namespace

std::expected<std::unique_ptr<TlsStream>, std::string> TlsConnect(
    int fd, const std::string& host, const std::string& ca_file) {
#if MBEDTLS_VERSION_MAJOR >= 3
  // TLS 1.3 and the PSA-backed ciphers need the PSA core up.
  static std::once_flag once;
  static psa_status_t psa = PSA_SUCCESS;
  std::call_once(once, [] { psa = psa_crypto_init(); });
  if (psa != PSA_SUCCESS) return std::unexpected("PSA crypto setup failed");
#endif
  auto stream = std::make_unique<MbedTlsStream>(fd);
  if (auto ok = stream->Handshake(host, ca_file); !ok) {
    return std::unexpected(ok.error());
  }
  return stream;
}

std::string TlsBackend() { return "mbedTLS " MBEDTLS_VERSION_STRING; }

}  // namespace aember::auth
