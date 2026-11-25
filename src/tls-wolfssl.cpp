// TLS through wolfSSL (GPL-2.0-only): the old backend, kept until the
// aember-resources SDK carries mbedTLS (see tls.h).
#include <format>
#include <mutex>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "tls.h"

namespace aember::auth {

namespace {

struct CtxDeleter {
  void operator()(WOLFSSL_CTX* c) const { wolfSSL_CTX_free(c); }
};
struct SslDeleter {
  void operator()(WOLFSSL* s) const { wolfSSL_free(s); }
};

class WolfSslStream : public TlsStream {
 public:
  WolfSslStream(std::unique_ptr<WOLFSSL_CTX, CtxDeleter> ctx,
                std::unique_ptr<WOLFSSL, SslDeleter> ssl)
      : ctx_(std::move(ctx)), ssl_(std::move(ssl)) {}

  ssize_t Read(char* buf, std::size_t n) override {
    const int r = wolfSSL_read(ssl_.get(), buf, static_cast<int>(n));
    if (r > 0) return r;
    const int err = wolfSSL_get_error(ssl_.get(), r);
    return err == WOLFSSL_ERROR_ZERO_RETURN || err == SOCKET_PEER_CLOSED_E
               ? 0
               : -1;
  }

  bool WriteAll(std::string_view data) override {
    return wolfSSL_write(ssl_.get(), data.data(),
                         static_cast<int>(data.size())) ==
           static_cast<int>(data.size());
  }

 private:
  std::unique_ptr<WOLFSSL_CTX, CtxDeleter> ctx_;  // outlives ssl_
  std::unique_ptr<WOLFSSL, SslDeleter> ssl_;
};

}  // namespace

std::expected<std::unique_ptr<TlsStream>, std::string> TlsConnect(
    int fd, const std::string& host, const std::string& ca_file) {
  static std::once_flag once;
  std::call_once(once, [] { wolfSSL_Init(); });
  std::unique_ptr<WOLFSSL_CTX, CtxDeleter> ctx{
      wolfSSL_CTX_new(wolfTLS_client_method())};
  if (!ctx) return std::unexpected("TLS setup failed");
  if (wolfSSL_CTX_load_verify_locations(ctx.get(), ca_file.c_str(), nullptr) !=
      WOLFSSL_SUCCESS) {
    return std::unexpected(std::format("cannot load CA {}", ca_file));
  }
  wolfSSL_CTX_set_verify(ctx.get(), WOLFSSL_VERIFY_PEER, nullptr);
  std::unique_ptr<WOLFSSL, SslDeleter> ssl{wolfSSL_new(ctx.get())};
  if (!ssl) return std::unexpected("TLS setup failed");
  wolfSSL_UseSNI(ssl.get(), WOLFSSL_SNI_HOST_NAME, host.data(),
                 static_cast<unsigned short>(host.size()));
  wolfSSL_check_domain_name(ssl.get(), host.c_str());
  wolfSSL_set_fd(ssl.get(), fd);
  if (wolfSSL_connect(ssl.get()) != WOLFSSL_SUCCESS) {
    char err[80] = {};
    wolfSSL_ERR_error_string_n(wolfSSL_get_error(ssl.get(), 0), err,
                               sizeof(err));
    return std::unexpected(std::format("TLS handshake with {}: {}", host, err));
  }
  return std::make_unique<WolfSslStream>(std::move(ctx), std::move(ssl));
}

std::string TlsBackend() { return "wolfSSL " LIBWOLFSSL_VERSION_STRING; }

}  // namespace aember::auth
