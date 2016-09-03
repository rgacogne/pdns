
#include "config.h"
#include "iputils.hh"
#include "tcpiohandler.hh"
#include "dolog.hh"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif /* HAVE_LIBSODIUM */

#ifdef HAVE_DNS_OVER_TLS
#ifdef HAVE_LIBSSL
#warning with openssl!
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER)
/* OpenSSL < 1.1.0 needs support for threading/locking in the calling application. */
static pthread_mutex_t *openssllocks;

extern "C" {
static void openssl_pthreads_locking_callback(int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(openssllocks[type]));

  }else {
    pthread_mutex_unlock(&(openssllocks[type]));
  }
}

static unsigned long openssl_pthreads_id_callback()
{
  return (unsigned long)pthread_self();
}
}

static void openssl_thread_setup()
{
  openssllocks = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

  for (int i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_init(&(openssllocks[i]), NULL);

  CRYPTO_set_id_callback(openssl_pthreads_id_callback);
  CRYPTO_set_locking_callback(openssl_pthreads_locking_callback);
}

static void openssl_thread_cleanup()
{
  CRYPTO_set_locking_callback(NULL);

  for (int i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(openssllocks[i]));
  }

  OPENSSL_free(openssllocks);
}

#else
static void openssl_thread_setup()
{
}

static void openssl_thread_cleanup()
{
}
#endif /* (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER) */

class OpenSSLTLSConnection: public TLSConnection
{
public:
  OpenSSLTLSConnection(int socket, unsigned int timeout, SSL_CTX* tlsCtx)
  {
    d_socket = socket;
    d_conn = SSL_new(tlsCtx);
    if (!d_conn) {
      vinfolog("Error creating TLS object");
      if (g_verbose) {
        ERR_print_errors_fp(stderr);
      }
      throw std::runtime_error("Error creating TLS object");
    }
    if (!SSL_set_fd(d_conn, d_socket)) {
      throw std::runtime_error("Error assigning socket");
    }
    int res = 0;
    do {
      res = SSL_accept(d_conn);
      if (res < 0) {
        handleIORequest(res, timeout);
      }
    }
    while (res < 0);

    if (res == 0) {
      throw std::runtime_error("Error accepting TLS connection");
    }
  }

  virtual ~OpenSSLTLSConnection() override
  {
    if (d_conn) {
      SSL_free(d_conn);
    }
  }

  void handleIORequest(int res, unsigned int timeout)
  {
    int error = SSL_get_error(d_conn, res);
    if (error == SSL_ERROR_WANT_READ) {
      res = waitForData(d_socket, timeout);
      if (res <= 0) {
        throw std::runtime_error("Error reading from TLS connection");
      }
    }
    else if (error == SSL_ERROR_WANT_WRITE) {
      res = waitForRWData(d_socket, false, timeout, 0);
      if (res <= 0) {
        throw std::runtime_error("Error waiting to write to TLS connection");
      }
    }
    else {
      throw std::runtime_error("Error writing to TLS connection");
    }
  }

  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout) override
  {
    size_t got = 0;
    do {
      int res = SSL_read(d_conn, ((char *)buffer) + got, (int) (bufferSize - got));
      if (res == 0) {
        throw std::runtime_error("Error reading from TLS connection");
      }
      else if (res < 0) {
        handleIORequest(res, readTimeout);
      }
      else {
        got += (size_t) res;
      }
    }
    while (got < bufferSize);

    return got;
  }

  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) override
  {
    size_t got = 0;
    do {
      int res = SSL_write(d_conn, ((char *)buffer) + got, (int) (bufferSize - got));
      if (res == 0) {
        throw std::runtime_error("Error writing to TLS connection");
      }
      else if (res < 0) {
        handleIORequest(res, writeTimeout);
      }
      else {
        got += (size_t) res;
      }
    }
    while (got < bufferSize);

    return got;
  }
  void close() override
  {
    if (d_conn) {
      SSL_shutdown(d_conn);
    }
  }
private:
  SSL* d_conn{nullptr};
};

class OpenSSLTLSIOCtx: public TLSCtx
{
public:
  OpenSSLTLSIOCtx(const TLSFrontend& fe)
  {
    static const int sslOptions =
      SSL_OP_NO_SSLv2 |
      SSL_OP_NO_SSLv3 |
      SSL_OP_NO_COMPRESSION |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
      SSL_OP_SINGLE_DH_USE |
      SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_CIPHER_SERVER_PREFERENCE;

    if (s_users.fetch_add(1) == 0) {
      ERR_load_crypto_strings();
      OpenSSL_add_ssl_algorithms();
      openssl_thread_setup();
    }

    d_tlsCtx = SSL_CTX_new(SSLv23_server_method());
    if (!d_tlsCtx) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("Error creating TLS context on " + fe.d_addr.toStringWithPort());
    }

    /* use the internal built-in cache to store sessions */
    SSL_CTX_set_session_cache_mode(d_tlsCtx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_options(d_tlsCtx, sslOptions);
    SSL_CTX_set_ecdh_auto(d_tlsCtx, 1);
    SSL_CTX_use_certificate_file(d_tlsCtx, fe.d_certFile.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(d_tlsCtx, fe.d_keyFile.c_str(), SSL_FILETYPE_PEM);

    if (!fe.d_ciphers.empty()) {
      SSL_CTX_set_cipher_list(d_tlsCtx, fe.d_ciphers.c_str());
    }

    if (!fe.d_caFile.empty()) {
      BIO *bio = BIO_new(BIO_s_file());
      if (!bio) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error creating TLS BIO for " + fe.d_addr.toStringWithPort());
      }

      if (BIO_read_filename(bio, fe.d_caFile.c_str()) <= 0) {
        BIO_free(bio);
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error reading TLS chain from file " + fe.d_caFile + " for " + fe.d_addr.toStringWithPort());
      }

      X509* x509 = nullptr;
      while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != nullptr) {
        if (!SSL_CTX_add_extra_chain_cert(d_tlsCtx, x509)) {
          ERR_print_errors_fp(stderr);
          BIO_free(bio);
          X509_free(x509);
          BIO_free(bio);
          throw std::runtime_error("Error reading certificate from chain " + fe.d_caFile + " for " + fe.d_addr.toStringWithPort());
        }
      }
      BIO_free(bio);
    }
  }

  virtual ~OpenSSLTLSIOCtx() override
  {
    if (d_tlsCtx) {
      SSL_CTX_free(d_tlsCtx);
    }

    if (s_users.fetch_sub(1) == 1) {
      ERR_free_strings();

      EVP_cleanup();

      CONF_modules_finish();
      CONF_modules_free();
      CONF_modules_unload(1);

      CRYPTO_cleanup_all_ex_data();
      openssl_thread_cleanup();
    }
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout) override
  {
    return std::unique_ptr<OpenSSLTLSConnection>(new OpenSSLTLSConnection(socket, timeout, d_tlsCtx));
  }
private:
  SSL_CTX* d_tlsCtx{nullptr};
  static std::atomic<uint64_t> s_users;
};

std::atomic<uint64_t> OpenSSLTLSIOCtx::s_users(0);

#endif /* HAVE_LIBSSL */

#ifdef HAVE_S2N
#warning with s2n!
#include <s2n.h>
#include <fstream>

class S2NTLSConnection: public TLSConnection
{
public:
  S2NTLSConnection(int socket, unsigned int timeout, struct s2n_config* tlsCtx)
  {
    d_socket = socket;

    d_conn = s2n_connection_new(S2N_SERVER);
    if (!d_conn) {
      vinfolog("Error creating TLS object");
      throw std::runtime_error("Error creating TLS object");
    }

    if (s2n_connection_set_config(d_conn, tlsCtx) < 0) {
      throw std::runtime_error("Error assigning configuration");
    }

    if (s2n_connection_set_fd(d_conn, d_socket) < 0) {
      throw std::runtime_error("Error assigning socket");
    }

    s2n_blocked_status status;
    int res = 0;
    do {
      res = s2n_negotiate(d_conn, &status);

      if (res < 0 && !status) {
        int savedErrno = s2n_errno;
        vinfolog("Error accepting TLS connection: %s (%s)", s2n_strerror(savedErrno, "EN"), s2n_connection_get_alert(d_conn));
        throw std::runtime_error("Error accepting TLS connection");
      }
      if (status) {
        handleIORequest(status, timeout);
      }
    }
    while (status);
  }

  virtual ~S2NTLSConnection() override
  {
    if (d_conn) {
      s2n_connection_free(d_conn);
    }
  }

  void handleIORequest(s2n_blocked_status status, unsigned int timeout)
  {
    int res = 0;
    if (status == S2N_BLOCKED_ON_READ) {
      res = waitForData(d_socket, timeout);
      if (res <= 0) {
        throw std::runtime_error("Error reading from TLS connection");
      }
    }
    else if (status == S2N_BLOCKED_ON_WRITE) {
      res = waitForRWData(d_socket, false, timeout, 0);
      if (res <= 0) {
        throw std::runtime_error("Error waiting to write to TLS connection");
      }
    }
    else {
      throw std::runtime_error("Error writing to TLS connection");
    }
  }

  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout) override
  {
    size_t got = 0;
    s2n_blocked_status status;
    do {
      ssize_t res = s2n_recv(d_conn, ((char *)buffer) + got, bufferSize - got, &status);
      if (res == 0) {
        throw std::runtime_error("Error reading from TLS connection");
      }
      else if (res > 0) {
        got += (size_t) res;
      }
      else if (res < 0 && !status) {
        throw std::runtime_error("Error reading from TLS connection");
      }
      if (got < bufferSize && status) {
        handleIORequest(status, readTimeout);
      }
    }
    while (got < bufferSize);

    return got;
  }

  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) override
  {
    size_t got = 0;
    s2n_blocked_status status;
    do {
      ssize_t res = s2n_send(d_conn, ((char *)buffer) + got, bufferSize - got, &status);
      if (res == 0) {
        throw std::runtime_error("Error writing to TLS connection");
      }
      else if (res > 0) {
        got += (size_t) res;
      }
      else if (res < 0 && !status) {
        throw std::runtime_error("Error writing to TLS connection");
      }
      if (got < bufferSize && status) {
        handleIORequest(status, writeTimeout);
      }
    }
    while (got < bufferSize);

    return got;
  }

  void close() override
  {
    if (d_conn) {
      s2n_blocked_status status;
      s2n_shutdown(d_conn, &status);
    }
  }

private:
  struct s2n_connection *d_conn{nullptr};
};

class S2NTLSIOCtx: public TLSCtx
{
public:
  S2NTLSIOCtx(const TLSFrontend& fe)
  {
    if (s_users.fetch_add(1) == 0) {
      s2n_init();
    }

    d_tlsCtx = s2n_config_new();
    if (!d_tlsCtx) {
      throw std::runtime_error("Error creating TLS context on " + fe.d_addr.toStringWithPort());
    }

    std::ifstream certStream(fe.d_certFile);
    std::string certContent((std::istreambuf_iterator<char>(certStream)),
                            (std::istreambuf_iterator<char>()));
    std::ifstream keyStream(fe.d_keyFile);
    std::string keyContent((std::istreambuf_iterator<char>(keyStream)),
                           (std::istreambuf_iterator<char>()));

    if (s2n_config_add_cert_chain_and_key(d_tlsCtx, certContent.c_str(), keyContent.c_str()) < 0) {
      s2n_config_free(d_tlsCtx);
      throw std::runtime_error("Error assigning certificate (from " + fe.d_certFile + ") and key (from " + fe.d_keyFile + ")");
    }
    certContent.clear();
    keyContent.clear();

    if (!fe.d_ciphers.empty()) {
      if (s2n_config_set_cipher_preferences(d_tlsCtx, fe.d_ciphers.c_str()) < 0) {
        warnlog("Error setting up TLS cipher preferences to %s, skipping.", fe.d_ciphers.c_str());
      }
    }

    /* apparently s2n doesn't support TLS tickets:
       https://github.com/awslabs/s2n/issues/4
       https://github.com/awslabs/s2n/issues/262
    */

    /* we should implemente TLS sessions by providing the following callbacks:
       s2n_config_set_cache_store_callback(struct s2n_config *config, int (*cache_store)(void *, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size), void *data);
       s2n_config_set_cache_retrieve_callback(struct s2n_config *config, int (*cache_retrieve)(void *, const void *key, uint64_t key_size, void *value, uint64_t *value_size), void *data):
       s2n_config_set_cache_delete_callback(struct s2n_config *config, int (*cache_delete))(void *, const void *key, uint64_t key_size), void *data);
    */
  }

  virtual ~S2NTLSIOCtx() override
  {
    if (d_tlsCtx) {
      s2n_config_free(d_tlsCtx);
    }

    if (s_users.fetch_sub(1) == 1) {
      s2n_cleanup();
    }
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout) override
  {
    return std::unique_ptr<S2NTLSConnection>(new S2NTLSConnection(socket, timeout, d_tlsCtx));
  }

private:
  struct s2n_config* d_tlsCtx{nullptr};
  static std::atomic<uint64_t> s_users;
};

std::atomic<uint64_t> S2NTLSIOCtx::s_users(0);
#endif /* HAVE_S2N */

#define HAVE_GNUTLS 1
#ifdef HAVE_GNUTLS
#warning with gnutls!
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

class GnuTLSConnection: public TLSConnection
{
public:

  GnuTLSConnection(int socket, unsigned int timeout, const gnutls_certificate_credentials_t creds, const gnutls_priority_t priorityCache, const gnutls_datum_t& ticketsKey)
  {
    d_socket = socket;

    if (gnutls_init(&d_conn, GNUTLS_SERVER | GNUTLS_NO_SIGNAL) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error creating TLS connection");
    }

    if (gnutls_credentials_set(d_conn, GNUTLS_CRD_CERTIFICATE, creds) != GNUTLS_E_SUCCESS) {
      gnutls_deinit(d_conn);
      throw std::runtime_error("Error setting certificate and key to TLS connection");
    }

    if (gnutls_priority_set(d_conn, priorityCache) != GNUTLS_E_SUCCESS) {
      gnutls_deinit(d_conn);
      throw std::runtime_error("Error setting ciphers to TLS connection");
    }

    if (ticketsKey.data != nullptr && ticketsKey.size > 0) {
      if (gnutls_session_ticket_enable_server(d_conn, &ticketsKey) != GNUTLS_E_SUCCESS) {
        gnutls_deinit(d_conn);
        throw std::runtime_error("Error setting the tickets key to TLS connection");
      }
    }

    gnutls_transport_set_int(d_conn, d_socket);
    /* timeouts are in milliseconds */
    gnutls_handshake_set_timeout(d_conn, timeout * 1000);
    gnutls_record_set_timeout(d_conn, timeout * 1000);

    int ret = 0;
    do {
      ret = gnutls_handshake(d_conn);
    }
    while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
  }

  virtual ~GnuTLSConnection() override
  {
    if (d_conn) {
      gnutls_deinit(d_conn);
    }
  }

  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout) override
  {
    size_t got = 0;

    do {
      ssize_t res = gnutls_record_recv(d_conn, ((char *)buffer) + got, bufferSize - got);
      if (res == 0) {
        throw std::runtime_error("Error reading from TLS connection");
      }
      else if (res > 0) {
        got += (size_t) res;
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Error reading from TLS connection");
        }
        warnlog("Warning, non-fatal error while reading from TLS connection: %s", gnutls_strerror(res));
      }
    }
    while (got < bufferSize);

    return got;
  }

  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) override
  {
    size_t got = 0;

    do {
      ssize_t res = gnutls_record_send(d_conn, ((char *)buffer) + got, bufferSize - got);
      if (res == 0) {
        throw std::runtime_error("Error writing to TLS connection");
      }
      else if (res > 0) {
        got += (size_t) res;
      }
      else if (res < 0) {
        if (gnutls_error_is_fatal(res)) {
          throw std::runtime_error("Error writing to TLS connection");
        }
        warnlog("Warning, non-fatal error while writing to TLS connection: %s", gnutls_strerror(res));
      }
    }
    while (got < bufferSize);

    return got;
  }

  void close() override
  {
    if (d_conn) {
      gnutls_bye(d_conn, GNUTLS_SHUT_WR);
    }
  }

private:
  gnutls_session_t d_conn{nullptr};
};

class GnuTLSIOCtx: public TLSCtx
{
public:
  GnuTLSIOCtx(const TLSFrontend& fe)
  {
    if (gnutls_certificate_allocate_credentials(&d_creds) != GNUTLS_E_SUCCESS) {
      throw std::runtime_error("Error allocating credentials for TLS context on " + fe.d_addr.toStringWithPort());
    }

    if (gnutls_certificate_set_x509_key_file2(d_creds, fe.d_certFile.c_str(), fe.d_keyFile.c_str(), GNUTLS_X509_FMT_PEM, nullptr, GNUTLS_PKCS_PLAIN) != GNUTLS_E_SUCCESS) {
      gnutls_certificate_free_credentials(d_creds);
      throw std::runtime_error("Error loading certificate and key for TLS context on " + fe.d_addr.toStringWithPort());
    }

    if (gnutls_certificate_set_known_dh_params(d_creds, GNUTLS_SEC_PARAM_MEDIUM) != GNUTLS_E_SUCCESS) {
      gnutls_certificate_free_credentials(d_creds);
      throw std::runtime_error("Error setting DH params for TLS context on " + fe.d_addr.toStringWithPort());
    }

    if (gnutls_priority_init(&d_priorityCache, fe.d_ciphers.empty() ? "NORMAL" : fe.d_ciphers.c_str(), nullptr) != GNUTLS_E_SUCCESS) {
      warnlog("Error setting up TLS cipher preferences to %s, skipping.", fe.d_ciphers.c_str());
    }

    /* XXX: We need to handle regular rotation of the key */
    if (gnutls_session_ticket_key_generate(&d_ticketsKey) != GNUTLS_E_SUCCESS) {
      gnutls_certificate_free_credentials(d_creds);
      throw std::runtime_error("Error generating tickets key for TLS context on " + fe.d_addr.toStringWithPort());
    }

#ifdef HAVE_LIBSODIUM
    sodium_mlock(d_ticketsKey.data, d_ticketsKey.size);
#endif /* HAVE_LIBSODIUM */
  }

  virtual ~GnuTLSIOCtx() override
  {
    if (d_ticketsKey.data != nullptr && d_ticketsKey.size > 0) {
#ifdef HAVE_LIBSODIUM
      sodium_munlock(d_ticketsKey.data, d_ticketsKey.size);
#else
      gnutls_memset(d_ticketsKey.data, 0, d_ticketsKey.size);
#endif /* HAVE_LIBSODIUM */
    }
    gnutls_free(d_ticketsKey.data);

    if (d_creds) {
      gnutls_certificate_free_credentials(d_creds);
    }
    if (d_priorityCache) {
      gnutls_priority_deinit(d_priorityCache);
    }
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout) override
  {
    return std::unique_ptr<GnuTLSConnection>(new GnuTLSConnection(socket, timeout, d_creds, d_priorityCache, d_ticketsKey));
  }

private:
  gnutls_certificate_credentials_t d_creds{nullptr};
  gnutls_priority_t d_priorityCache{nullptr};
  gnutls_datum_t d_ticketsKey{nullptr, 0};
};

#endif /* HAVE_GNUTLS */

#endif /* HAVE_DNS_OVER_TLS */

bool TLSFrontend::setupTLS()
{
#ifdef HAVE_DNS_OVER_TLS
  /* get the "best" available provider */
  if (!d_provider.empty()) {
#ifdef HAVE_GNUTLS
    if (d_provider == "gnutls") {
      d_ctx = std::make_shared<GnuTLSIOCtx>(*this);
      return true;
    }
#endif /* HAVE_S2N */
#ifdef HAVE_S2N
    if (d_provider == "s2n") {
      d_ctx = std::make_shared<S2NTLSIOCtx>(*this);
      return true;
    }
#endif /* HAVE_S2N */
#ifdef HAVE_LIBSSL
    if (d_provider == "openssl") {
      d_ctx = std::make_shared<OpenSSLTLSIOCtx>(*this);
      return true;
    }
#endif /* HAVE_LIBSSL */
  }
#ifdef HAVE_GNUTLS
  d_ctx = std::make_shared<GnuTLSIOCtx>(*this);
#else /* HAVE_GNUTLS */
#ifdef HAVE_S2N
  d_ctx = std::make_shared<S2NTLSIOCtx>(*this);
#else /* HAVE_S2N */
#ifdef HAVE_LIBSSL
  d_ctx = std::make_shared<OpenSSLTLSIOCtx>(*this);
#endif /* HAVE_LIBSSL */
#endif /* HAVE_S2N */
#endif /* HAVE_GNUTLS */

#endif /* HAVE_DNS_OVER_TLS */
  return true;
}
