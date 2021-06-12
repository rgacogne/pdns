/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#include <stdexcept>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base64.hh"
#include "credentials.hh"
#include "misc.hh"

static size_t const pwhash_max_size = 128U; /* maximum size of the output */
static size_t const pwhash_output_size = 32U;
static unsigned int const pwhash_salt_size = 16U;
static uint64_t const pwhash_work_factor = 1024U; /* N */
static uint64_t const pwhash_parallel_factor = 1U; /* p */
static uint64_t const pwhash_block_size_paramter = 8U; /* r */

/* for now we only support one algo, with fixed parameters, but we might have to change that later */
static std::string const pwhash_prefix = "$scrypt$n=1024$p=1$r=8$";
static size_t const pwhash_prefix_size = pwhash_prefix.size();

#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
static std::string hashPasswordInternal(const std::string& password, const std::string& salt)
{
  std::string out;
  auto pctx = std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)>(EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr), EVP_PKEY_CTX_free);
  if (!pctx) {
    throw std::runtime_error("Error getting a scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_derive_init(pctx.get()) <= 0) {
    throw std::runtime_error("Error intializing the scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_CTX_set1_pbe_pass(pctx.get(), reinterpret_cast<const unsigned char*>(password.data()), password.size()) <= 0) {
    throw std::runtime_error("Error adding the password to the scrypt context to hash the supplied password");
 }

  if (EVP_PKEY_CTX_set1_scrypt_salt(pctx.get(), salt.data(), salt.size()) <= 0) {
    throw std::runtime_error("Error adding the salt to the scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_CTX_set_scrypt_N(pctx.get(), pwhash_work_factor) <= 0) {
    throw std::runtime_error("Error setting the work factor to the scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_CTX_set_scrypt_r(pctx.get(), pwhash_block_size_paramter) <= 0) {
    throw std::runtime_error("Error setting the block size to the scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_CTX_set_scrypt_p(pctx.get(), pwhash_parallel_factor) <= 0) {
    throw std::runtime_error("Error setting the parallel factor to the scrypt context to hash the supplied password");
  }

  out.resize(pwhash_output_size);
#ifdef HAVE_LIBSODIUM
  sodium_mlock(out.data(), out.size());
#endif
  size_t outlen = out.size();

  if (EVP_PKEY_derive(pctx.get(), reinterpret_cast<unsigned char*>(out.data()), &outlen) <= 0 || outlen != pwhash_output_size) {
    throw std::runtime_error("Error deriving the output from the scrypt context to hash the supplied password");
  }

  return out;
}
#endif

std::string hashPassword(const std::string& password)
{
#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
  std::string result;
  result.reserve(pwhash_max_size);

#ifdef HAVE_LIBSODIUM
  sodium_mlock(result.data(), result.size());
#endif

  result.append(pwhash_prefix);
  /* generate a random salt */
  std::string salt;
  salt.resize(pwhash_salt_size);

  if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size()) != 1) {
    throw std::runtime_error("Error while generating a salt to hash the supplied password");
  }

  result.append(Base64Encode(salt));
  result.append("$");

  auto out = hashPasswordInternal(password, salt);

  // XXX: the current b64 API does not allow us to lock the memory
  result.append(Base64Encode(out));

  return result;
#else
  throw std::runtime_error("Hashing a password requires scrypt support in OpenSSL, and it is not available");
#endif
}

bool verifyPassword(const std::string& hash, const std::string& password)
{
  if (!isPasswordHashed(hash)) {
    return false;
  }

#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
  auto saltPos = pwhash_prefix.size();

  auto saltEnd = hash.find('$', saltPos + 1);
  if (saltEnd == std::string::npos) {
    return false;
  }

  auto b64Salt = hash.substr(saltPos, saltEnd - saltPos);
  std::string salt;
  salt.reserve(pwhash_salt_size);
  B64Decode(b64Salt, salt);

  if (salt.size() != pwhash_salt_size) {
    return false;
  }

  std::string tentative;
  tentative.reserve(pwhash_output_size);
  B64Decode(hash.substr(saltEnd + 1), tentative);

  if (tentative.size() != pwhash_output_size) {
    return false;
  }

  auto expected = hashPasswordInternal(password, salt);

  return constantTimeStringEquals(expected, tentative);
#else
  throw std::runtime_error("Verifying a hashed password requires scrypt support in OpenSSL, and it is not available");
#endif
}

bool isPasswordHashed(const std::string& password)
{
#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
  if (password.size() < pwhash_prefix_size || password.size() > pwhash_max_size) {
    return false;
  }

  if (!boost::starts_with(password, pwhash_prefix)) {
    return false;
  }

  auto saltEnd = password.find('$', pwhash_prefix.size() + 1);
  if (saltEnd == std::string::npos) {
    return false;
  }

  return true;
#else
  return false;
#endif
}

/* if the password is in cleartext and hashing is available,
   the hashed form will be kept in memory */
CredentialsHolder::CredentialsHolder(std::string&& password, bool hashPlaintext)
{
  bool locked = false;

  if (isHashingAvailable()) {
    if (!isPasswordHashed(password)) {
      if (hashPlaintext) {
        d_credentials = hashPassword(password);
        locked = true;
        d_isHashed = true;
      }
    }
    else {
      d_wasHashed = true;
      d_isHashed = true;
      d_credentials = std::move(password);
    }
  }

  if (!d_isHashed) {
    d_fallbackHashPerturb = random();
    d_fallbackHash = burtle(reinterpret_cast<const unsigned char*>(password.data()), password.size(), d_fallbackHashPerturb);
    d_credentials = std::move(password);
  }

  if (!locked) {
#ifdef HAVE_LIBSODIUM
    sodium_mlock(d_credentials.data(), d_credentials.size());
#endif
  }
}

CredentialsHolder::~CredentialsHolder()
{
#ifdef HAVE_LIBSODIUM
  sodium_munlock(d_credentials.data(), d_credentials.size());
#endif
  d_fallbackHashPerturb = 0;
  d_fallbackHash = 0;
}

bool CredentialsHolder::matches(const std::string& password) const
{
  if (d_isHashed) {
    return verifyPassword(d_credentials, password);
  }
  else {
    uint32_t fallback = burtle(reinterpret_cast<const unsigned char*>(password.data()), password.size(), d_fallbackHashPerturb);
    if (fallback != d_fallbackHash) {
      return false;
    }

    return constantTimeStringEquals(password, d_credentials);
  }
}

bool CredentialsHolder::isHashingAvailable()
{
#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
  return true;
#else
  return false;
#endif
}

#include <signal.h>
#include <termios.h>

std::string CredentialsHolder::readFromTerminal()
{
  struct termios term;
  struct termios oterm;
  memset(&term, 0, sizeof(term));
  term.c_lflag |= ECHO;
  memset(&oterm, 0, sizeof(oterm));
  oterm.c_lflag |= ECHO;
  bool restoreTermSettings = false;
  int termAction = TCSAFLUSH;
#ifdef TCSASOFT
  termAction |= TCSASOFT
#endif

  FDWrapper input(open("/dev/tty", O_RDONLY));
  if (int(input) != -1) {
    if (tcgetattr(input, &oterm) == 0) {
      memcpy(&term, &oterm, sizeof(term));
      term.c_lflag &= ~(ECHO | ECHONL);
      tcsetattr(input, termAction, &term);
      restoreTermSettings = true;
    }
  }
  else {
    input = FDWrapper(dup(STDIN_FILENO));
  }
  FDWrapper output(open("/dev/tty", O_WRONLY));
  if (int(output) == -1) {
    output = FDWrapper(dup(STDERR_FILENO));
  }

  struct std::map<int, struct sigaction> signals;
  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = [](int s) { };
  sigaction(SIGALRM, &sa, &signals[SIGALRM]);
  sigaction(SIGHUP, &sa, &signals[SIGHUP]);
  sigaction(SIGINT, &sa, &signals[SIGINT]);
  sigaction(SIGPIPE, &sa, &signals[SIGPIPE]);
  sigaction(SIGQUIT, &sa, &signals[SIGQUIT]);
  sigaction(SIGTERM, &sa, &signals[SIGTERM]);
  sigaction(SIGTSTP, &sa, &signals[SIGTSTP]);
  sigaction(SIGTTIN, &sa, &signals[SIGTTIN]);
  sigaction(SIGTTOU, &sa, &signals[SIGTTOU]);

  std::string buffer;
  /* let's allocate a huge buffer now to prevent reallocation,
     which would leave parts of the buffer around */
  buffer.reserve(512);

  for (;;) {
    char ch = '\0';
    auto got = read(input, &ch, 1);
    if (got == 1 && ch != '\n' && ch != '\r') {
      buffer.push_back(ch);
    }
    else {
      break;
    }
  }

  if (!(term.c_lflag & ECHO)) {
    if (write(output, "\n", 1) != 1) {
      /* the compiler _really_ wants the result of write() to be checked.. */
    }
  }

  if (restoreTermSettings) {
    tcsetattr(input, termAction, &oterm);
  }

  for (const auto& sig : signals) {
    sigaction(sig.first, &sig.second, nullptr);
  }

#ifdef HAVE_LIBSODIUM
  sodium_mlock(buffer.data(), buffer.size());
#endif

  return buffer;
}
