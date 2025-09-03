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
#pragma once
#include "config.h"
#include <array>
#include <string>
#include <cstdint>
#include <cstring>

#if defined(HAVE_LIBSODIUM)
#include <sodium.h>
#endif

namespace dnsdist::crypto::authenticated
{
struct Nonce
{
  Nonce() = default;
  Nonce(const Nonce&) = default;
  Nonce(Nonce&&) = default;
  Nonce& operator=(const Nonce&) = default;
  Nonce& operator=(Nonce&&) = default;
  ~Nonce() = default;

  void init();
  void merge(const Nonce& lower, const Nonce& higher);
  void increment();

  static constexpr size_t getSize()
  {
    return s_size;
  }

private:
#if defined(HAVE_LIBSODIUM)
  static constexpr size_t s_size{crypto_secretbox_NONCEBYTES};
#elif defined(HAVE_LIBCRYPTO)
  // IV is 96 bits
  static constexpr size_t s_size{12U};
#else
  static constexpr size_t s_size{1U};
#endif
public:
  std::array<unsigned char, s_size> value{};
};

std::string encryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce = true);
std::string decryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce = true);
std::string newKey(bool base64Encoded = true);
bool isValidKey(const std::string& key);

constexpr size_t getEncryptedSize(size_t plainTextSize)
{
#if defined(HAVE_LIBSODIUM)
  return plainTextSize + crypto_secretbox_MACBYTES;
#elif defined(HAVE_LIBCRYPTO)
  return plainTextSize + 16;
#else
  return plainTextSize;
#endif
}
}
