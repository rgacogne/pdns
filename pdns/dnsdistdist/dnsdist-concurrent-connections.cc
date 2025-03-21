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

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include <utility>

#include "circular_buffer.hh"
#include "dnsdist-configuration.hh"
#include "lock.hh"

namespace dnsdist
{

static constexpr size_t NB_SHARDS = 10;
static constexpr size_t NB_BUCKETS = 5;
static constexpr size_t MAX_TCP_CONNECTIONS_PER_MINUTE = 1000;

struct ClientActivity
{
  uint64_t tcpConnections{0};
  uint64_t tlsNewSessions{0}; /* without resumption */
  uint64_t tlsResumedSessions{0};
  time_t bucketEndTime{0};
};

struct ClientEntry
{
  mutable boost::circular_buffer<ClientActivity> d_activity;
  ComboAddress d_addr;
  mutable uint64_t d_concurrentConnections{0};
  mutable time_t d_bannedUntil{0};
  time_t d_lastSeen{0};
};

struct TimeTag
{
};
struct AddressTag
{
};

using map_t = boost::multi_index_container<
  ClientEntry,
  boost::multi_index::indexed_by<
    boost::multi_index::hashed_unique<boost::multi_index::tag<AddressTag>,
                                      boost::multi_index::member<ClientEntry, ComboAddress, &ClientEntry::d_addr>, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>,
    boost::multi_index::ordered_non_unique<boost::multi_index::tag<TimeTag>,
                                           boost::multi_index::member<ClientEntry, time_t, &ClientEntry::d_lastSeen>>>>;

static std::vector<LockGuarded<map_t>> s_tcpClientsConnectionMetrics{10};

static size_t getShardID(const ComboAddress& from)
{
  auto hash = ComboAddress::addressOnlyHash()(from);
  return hash % NB_SHARDS;
}

static bool checkTCPConnectionsRate(const boost::circular_buffer<ClientActivity>& activity, time_t now)
{
  uint64_t bucketsConsidered = 0;
  uint64_t connectionsSeen = 0;
  time_t cutOff = now - (NB_BUCKETS * 60);
  for (const auto& entry : activity) {
    if (entry.bucketEndTime < cutOff) {
      continue;
    }
    ++bucketsConsidered;
    connectionsSeen += entry.tcpConnections;
  }
  if (bucketsConsidered == 0) {
    return true;
  }
  auto rate = connectionsSeen / bucketsConsidered;
  if (rate > MAX_TCP_CONNECTIONS_PER_MINUTE) {
    cerr<<"rate is "<<rate<<": "<<connectionsSeen<<" over "<<bucketsConsidered<<" buckets"<<endl;
  }
  return rate <= MAX_TCP_CONNECTIONS_PER_MINUTE;
}

void IncomingConcurrentTCPConnectionsManager::cleanup(time_t now)
{
  time_t cutOff = now - (NB_BUCKETS * 60);
  for (auto& shard : s_tcpClientsConnectionMetrics) {
    auto db = shard.lock();
    auto& index = db->get<TimeTag>();
    for (auto entry = index.begin(); entry != index.end();) {
      if (entry->d_lastSeen >= cutOff) {
        /* this index is ordered on timestamps,
           so the first valid entry we see means we are done */
        break;
      }

      cerr<<"removing expired entry for "<<entry->d_addr.toString()<<endl;
      entry = index.erase(entry);
    }
  }
}

IncomingConcurrentTCPConnectionsManager::NewConnectionResult IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(const ComboAddress& from)
{
  const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
  const auto maxConnsPerClient = immutable.d_maxTCPConnectionsPerClient;
  const auto threshold = immutable.d_tcpConnectionsOverloadThreshold;
  if (maxConnsPerClient == 0) {
    return NewConnectionResult::Allowed;
  }

  auto now = time(nullptr);
  auto updateActivity = [now](ClientEntry& entry) {
    ++entry.d_concurrentConnections;
    entry.d_lastSeen = now;
    {
      auto& activity = entry.d_activity;
      if (activity.empty() || activity.front().bucketEndTime < now) {
        activity.push_front(ClientActivity{1, 0, 0, now + 60});
      }
      ++activity.front().tcpConnections;
    }
  };

  auto checkConnectionAllowed = [now, from, maxConnsPerClient, threshold](const ClientEntry& entry) {
    if (entry.d_bannedUntil != 0 && entry.d_bannedUntil < now) {
      cerr<<"dropping connection from "<<from.toString()<<": banned"<<endl;
      return NewConnectionResult::Denied;
    }
    if (entry.d_concurrentConnections >= maxConnsPerClient) {
      cerr<<"dropping connection from "<<from.toString()<<": too many conns"<<endl;
      return NewConnectionResult::Denied;
    }
    if (!checkTCPConnectionsRate(entry.d_activity, now)) {
      cerr<<"dropping connection from "<<from.toString()<<": rate"<<endl;
      return NewConnectionResult::Denied;
    }

    auto current = (100 * entry.d_concurrentConnections) / maxConnsPerClient;
    if (threshold == 0 || current < threshold) {
      return NewConnectionResult::Allowed;
    }
    cerr<<"restricting connection from "<<from.toString()<<": too many conns"<<endl;
    return NewConnectionResult::Restricted;
  };

  {
    auto shardID = getShardID(from);
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    const auto& entry = db->find(from);
    if (entry == db->end()) {
      ClientEntry newEntry;
      newEntry.d_activity.set_capacity(NB_BUCKETS);
      newEntry.d_addr = from;
      newEntry.d_concurrentConnections = 1;
      newEntry.d_lastSeen = now;
      db->insert(std::move(newEntry));
      cerr<<"inserting new entry for "<<from.toString()<<endl;
      return NewConnectionResult::Allowed;
    }
    auto result = checkConnectionAllowed(*entry);
    if (result != NewConnectionResult::Denied) {
      db->modify(entry, updateActivity);
    }
    return result;
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
  auto shardID = getShardID(from);
  {
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    auto it = db->find(from);
    if (it == db->end()) {
      return false;
    }
    count = it->d_concurrentConnections;
  }

  auto current = (100 * count) / maxConnsPerClient;
  return current >= immutable.d_tcpConnectionsOverloadThreshold;
}

void IncomingConcurrentTCPConnectionsManager::banClientFor(const ComboAddress& from, time_t now, uint32_t seconds)
{
  auto shardID = getShardID(from);
  {
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    auto it = db->find(from);
    if (it == db->end()) {
      return;
    }
    db->modify(it, [now, seconds](ClientEntry& entry) {
      entry.d_lastSeen = now;
      entry.d_bannedUntil = now + seconds;
    });
  }
}

void IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(const ComboAddress& from)
{
  const auto maxConnsPerClient = dnsdist::configuration::getImmutableConfiguration().d_maxTCPConnectionsPerClient;
  if (maxConnsPerClient == 0) {
    return;
  }
  auto shardID = getShardID(from);
  {
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    auto it = db->find(from);
    if (it == db->end()) {
      return;
    }
    auto& count = it->d_concurrentConnections;
    count--;
  }
}


}
