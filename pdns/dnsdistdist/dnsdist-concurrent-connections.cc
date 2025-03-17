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

#include "dnsdist-concurrent-connections.hh"

#include <unordered_map>
#include <utility>

#include "circular_buffer.hh"
#include "dnsdist-configuration.hh"
#include "lock.hh"

namespace dnsdist
{
struct ClientEntry
{
  LockGuarded<boost::circular_buffer<IncomingConcurrentTCPConnectionsManager::ClientActivity>> d_activity;
  uint64_t d_concurrentConnections{0};
  time_t d_bannedUntil{0};
  time_t d_lastSeen{0};
};

static LockGuarded<std::unordered_map<ComboAddress, std::unique_ptr<ClientEntry>, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>> s_tcpClientsConnectionMetrics;
static constexpr size_t NB_BUCKETS = 30;

void IncomingConcurrentTCPConnectionsManager::cleanup(time_t now)
{
  #warning TODO
}

bool IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(const ComboAddress& from)
{
  const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
  const auto maxConnsPerClient = immutable.d_maxTCPConnectionsPerClient;
  if (maxConnsPerClient == 0) {
    return true;
  }

  auto now = time(nullptr);
  auto updateActivity = [now](ClientEntry& entry) {
    entry.d_lastSeen = now;
    {
      auto activity = entry.d_activity.lock();
      if (activity->empty() || activity->front().time != now) {
        activity->push_front(ClientActivity{1, 0, 0, now});
      }
      ++activity->front().tcpConnections;
      return;
    }
  };

  auto updatedLockedAndEntryPresent = [from, now, maxConnsPerClient, &updateActivity](ClientEntry& entry) {
    if (entry.d_bannedUntil != 0 && entry.d_bannedUntil < now) {
      return false;
    }
    if (entry.d_concurrentConnections >= maxConnsPerClient) {
      return false;
    }
    updateActivity(entry);
    ++entry.d_concurrentConnections;
    cerr<<"updating existing entry for "<<from.toString()<<" new count is now "<<entry.d_concurrentConnections<<endl;
    return true;
  };

  {
    auto db = s_tcpClientsConnectionMetrics.lock();
    const auto& entry = db->find(from);
    if (entry == db->end()) {
      auto newEntry = std::make_unique<ClientEntry>();
      newEntry->d_activity.lock()->set_capacity(NB_BUCKETS);
      newEntry->d_concurrentConnections = 1;
      newEntry->d_lastSeen = now;
      db->emplace(from, std::move(newEntry));
      cerr<<"no existing entry for "<<from.toString()<<" we now have "<<db->size()<<" entries"<<endl;
      return true;
    }
    return updatedLockedAndEntryPresent(*entry->second);
  }
}

bool IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(const ComboAddress& from)
{
  const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
  const auto maxConnsPerClient = immutable.d_maxTCPConnectionsPerClient;
  if (immutable.d_tcpConnectionsOverloadThreshold == 0) {
    return false;
  }

  size_t count = 0;
  {
    auto db = s_tcpClientsConnectionMetrics.lock();
    auto it = db->find(from);
    if (it == db->end()) {
      return false;
    }
    count = it->second->d_concurrentConnections;
  }

  auto current = (100 * count) / maxConnsPerClient;
  return current >= immutable.d_tcpConnectionsOverloadThreshold;
}

void IncomingConcurrentTCPConnectionsManager::banClientFor(const ComboAddress& from, time_t now, uint32_t seconds)
{
  {
    auto db = s_tcpClientsConnectionMetrics.lock();
    auto& entry = (*db)[from];
    entry->d_lastSeen = now;
    entry->d_bannedUntil = now + seconds;
  }
}

void IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(const ComboAddress& from)
{
  const auto maxConnsPerClient = dnsdist::configuration::getImmutableConfiguration().d_maxTCPConnectionsPerClient;
  if (maxConnsPerClient == 0) {
    return;
  }
  {
    auto db = s_tcpClientsConnectionMetrics.lock();
    auto& count = db->at(from)->d_concurrentConnections;
    count--;
  }
}


}
