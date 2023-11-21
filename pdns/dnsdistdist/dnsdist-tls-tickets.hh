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

#include <atomic>
#include <memory>

#include "circular_buffer.hh"
#include "lock.hh"

namespace dnsdist::tls::tickets
{
/* From rfc5077 Section 4. Recommended Ticket Construction */
static constexpr size_t s_key_name_size = 16U;

class TLSTicketKeyInterface
{
public:
  virtual ~TLSTicketKeyInterface()
  {
  };
  [[nodiscard]] virtual bool nameMatches(const unsigned char name[s_key_name_size]) const = 0;
};

template <class TLSTicketKey>
class TLSTicketKeysRing
{
public:
  TLSTicketKeysRing(size_t capacity, time_t keyRotationDelay, bool supportMultipleKeys): d_ticketsKeyRotationDelay(keyRotationDelay), d_supportMultipleKeys(supportMultipleKeys)
  {
    d_rotatingTicketsKey.clear();
    d_ticketKeys.write_lock()->set_capacity(capacity);
  }

  [[nodiscard]] std::shared_ptr<TLSTicketKey> getEncryptionKey()
  {
    handleTicketsKeyRotation();
    return d_ticketKeys.read_lock()->front();
  }

  [[nodiscard]] std::shared_ptr<TLSTicketKey> getDecryptionKey(unsigned char name[s_key_name_size], bool& activeKey)
  {
    handleTicketsKeyRotation();
    {
      auto keys = d_ticketKeys.read_lock();
      for (auto& key : *keys) {
        if (key->nameMatches(name)) {
          activeKey = (key == keys->front());
          return key;
        }
      }
    }
    return nullptr;
  }

  [[nodiscard]] size_t getKeysCount()
  {
    return d_ticketKeys.read_lock()->size();
  }

  void loadTicketsKeys(const std::string& keyFile)
  {
    bool keyLoaded = false;
    std::ifstream file(keyFile);
    try {
      do {
        auto newKey = std::make_shared<TLSTicketKey>(file);
        addKey(std::move(newKey));
        keyLoaded = true;
        if (!d_supportMultipleKeys) {
          break;
        }
      }
      while (!file.fail());
    }
    catch (const std::exception& e) {
      /* if we haven't been able to load at least one key, fail */
      if (!keyLoaded) {
        throw;
      }
    }

    file.close();
    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }
  }

  void rotateTicketsKey(time_t now)
  {
    if (d_rotatingTicketsKey.test_and_set()) {
      /* someone is already rotating */
      return;
    }
    try {
      auto newKey = std::make_shared<TLSTicketKey>();
      addKey(std::move(newKey));
      if (d_ticketsKeyRotationDelay > 0) {
        d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
      }

      d_rotatingTicketsKey.clear();
    }
    catch (const std::runtime_error& e) {
      d_rotatingTicketsKey.clear();
      throw std::runtime_error(std::string("Error generating a new tickets key for TLS context:") + e.what());
    }
    catch (...) {
      d_rotatingTicketsKey.clear();
      throw;
    }
  }

  [[nodiscard]] time_t getNextRotation() const
  {
    return d_ticketsKeyNextRotation;
  }

private:
  void handleTicketsKeyRotation()
  {
    if (d_ticketsKeyRotationDelay == 0) {
      return;
    }

    const auto now = time(nullptr);
    if (now <= d_ticketsKeyNextRotation) {
      return;
    }

    rotateTicketsKey(now);
  }

  void addKey(std::shared_ptr<TLSTicketKey>&& newKey)
  {
    d_ticketKeys.write_lock()->push_front(std::move(newKey));
  }

  SharedLockGuarded<boost::circular_buffer<std::shared_ptr<TLSTicketKey> > > d_ticketKeys;
  time_t d_ticketsKeyRotationDelay{0};
  time_t d_ticketsKeyNextRotation{0};
  bool d_supportMultipleKeys{true};
  std::atomic_flag d_rotatingTicketsKey;
};

}
