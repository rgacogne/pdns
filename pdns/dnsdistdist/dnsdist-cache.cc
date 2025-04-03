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
#include <cinttypes>

#include "dnsdist.hh"
#include "dolog.hh"
#include "dnsparser.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-ecs.hh"
#include "ednssubnet.hh"
#include "packetcache.hh"
#include "base64.hh"

bool DNSDistPacketCache::CacheValue::isGhost() const
{
  return freq.inner.load() == -1;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): too cumbersome to change at this point
DNSDistPacketCache::DNSDistPacketCache(CacheSettings settings) :
  d_settings(std::move(settings))
{
  if (d_settings.d_maxEntries == 0) {
    throw std::runtime_error("Trying to create a 0-sized packet-cache");
  }

  if (d_settings.d_shardCount == 0) {
    d_settings.d_shardCount = 1;
  }

  d_shards.resize(d_settings.d_shardCount);

  for (auto& shard : d_shards) {
    shard.setSize(d_settings.d_maxEntries / d_settings.d_shardCount);
  }
}

bool DNSDistPacketCache::getClientSubnet(const PacketBuffer& packet, size_t qnameWireLength, boost::optional<Netmask>& subnet)
{
  uint16_t optRDPosition = 0;
  size_t remaining = 0;

  int res = dnsdist::getEDNSOptionsStart(packet, qnameWireLength, &optRDPosition, &remaining);

  if (res == 0) {
    size_t ecsOptionStartPosition = 0;
    size_t ecsOptionSize = 0;

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    res = getEDNSOption(reinterpret_cast<const char*>(&packet.at(optRDPosition)), remaining, EDNSOptionCode::ECS, &ecsOptionStartPosition, &ecsOptionSize);

    if (res == 0 && ecsOptionSize > (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {

      EDNSSubnetOpts eso;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      if (EDNSSubnetOpts::getFromString(reinterpret_cast<const char*>(&packet.at(optRDPosition + ecsOptionStartPosition + (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE))), ecsOptionSize - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), &eso)) {
        subnet = eso.getSource();
        return true;
      }
    }
  }

  return false;
}

bool DNSDistPacketCache::cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool receivedOverUDP, bool dnssecOK, const boost::optional<Netmask>& subnet) const
{
  if (cachedValue.queryFlags != queryFlags || cachedValue.dnssecOK != dnssecOK || cachedValue.receivedOverUDP != receivedOverUDP || cachedValue.qtype != qtype || cachedValue.qclass != qclass || cachedValue.qname != qname) {
    return false;
  }

  if (d_settings.d_parseECS && cachedValue.subnet != subnet) {
    return false;
  }

  return true;
}

void DNSDistPacketCache::CacheShard::evictSmall(CacheShard::ShardData& data, EvictionType evictionType)
{
  bool evicted = false;
  auto now = time(nullptr);
  while (!evicted && !data.d_smallFIFO.empty()) {
    auto key = data.d_smallFIFO.back();
    data.d_smallFIFO.pop_back();
    auto entryIt = data.d_map.find(key);
    if (entryIt == data.d_map.end()) {
      // entry has been (manually?) removed from the cache already,
      // move on
      if (evictionType == EvictionType::NeedRoomInFIFO) {
        return;
      }
      continue;
    }
    if (entryIt->second.validity <= now) {
      data.d_map.erase(entryIt);
      --d_entriesCount;
      evicted = true;
    }
    else if (entryIt->second.freq.inner.load() > 0) {
      // at least one hit, move it to main
      if (data.d_mainFIFO.full()) {
        evictMain(data, EvictionType::NeedRoomInFIFO);
      }
      entryIt->second.freq.inner.store(0);
      data.d_mainFIFO.push_front(key);
    }
    else {
      // never used, good bye, but we will keep it in ghost for a while
      entryIt->second.value.clear();
      entryIt->second.freq.inner.store(-1);
      if (data.d_ghostFIFO.full()) {
        auto ghostKey = data.d_ghostFIFO.back();
        data.d_ghostFIFO.pop_back();
        auto ghostIt = data.d_map.find(ghostKey);
        // the check might seem silly but we do not
        // remove an entry from the ghost FIFO when
        // we insert it again into main
        if (ghostIt != data.d_map.end() && ghostIt->second.isGhost()) {
          data.d_map.erase(ghostIt);
        }
      }
      data.d_ghostFIFO.push_front(key);
      --d_entriesCount;
      evicted = true;
    }
  }
}

void DNSDistPacketCache::CacheShard::evictMain(CacheShard::ShardData& data, EvictionType evictionType)
{
  bool evicted = false;
  auto now = time(nullptr);
  while (!evicted && !data.d_mainFIFO.empty()) {
    auto key = data.d_mainFIFO.back();
    data.d_mainFIFO.pop_back();
    auto entryIt = data.d_map.find(key);
    if (entryIt == data.d_map.end()) {
      // entry has been (manually?) removed from the cache already,
      // move on
      if (evictionType == EvictionType::NeedRoomInFIFO) {
        return;
      }
      continue;
    }
    auto freq = entryIt->second.freq.inner.load();
    if (freq > 0 && entryIt->second.validity > now) {
      // the entry has been useful, let's move it
      // to the front of the FIFO after decreasing
      // the frequency counter so it might be removed
      // eventually if it stops being usefull
      entryIt->second.freq.inner.store(static_cast<int8_t>(freq - 1U));
      data.d_mainFIFO.push_front(key);
    }
    else {
      // not used recently, bye
      data.d_map.erase(entryIt);
      --d_entriesCount;
      evicted = true;
    }
  }
}

void DNSDistPacketCache::CacheShard::evict(CacheShard::ShardData& data)
{
  if (data.d_smallFIFO.full()) {
    evictSmall(data, EvictionType::NeedRoomInMap);
  }
  else {
    evictMain(data, EvictionType::NeedRoomInMap);
  }
}

void DNSDistPacketCache::CacheShard::setSize(size_t maxSize)
{
  auto data = d_data.write_lock();
  const auto maxSizeDouble = static_cast<double>(maxSize);
  const auto mainFIFOSize = std::trunc(maxSizeDouble * (1.0 - s_smallSizeRatio));
  const auto ghostFIFOSize = std::trunc(maxSizeDouble * (1.0 - s_smallSizeRatio) / 2);
  const auto smallFIFOSize = std::trunc(maxSizeDouble * s_smallSizeRatio);
  if (smallFIFOSize < 1) {
    throw std::runtime_error("Trying to create a too small packet cache, please consider increasing the size or reducing the number of shards");
  }
  /* we reserve maxEntries + 1 to avoid rehashing from occurring
     when we get to maxEntries, as it means a load factor of 1 */
  data->d_map.reserve(static_cast<size_t>(maxSizeDouble * (1.0 + s_ghostSizeRatio)) + 1);
  data->d_mainFIFO.set_capacity(static_cast<size_t>(mainFIFOSize));
  data->d_smallFIFO.set_capacity(static_cast<size_t>(smallFIFOSize));
  data->d_ghostFIFO.set_capacity(static_cast<size_t>(ghostFIFOSize));
}

void DNSDistPacketCache::insertLocked(CacheShard& shard, CacheShard::ShardData& data, uint32_t key, CacheValue&& newValue)
{
  while (data.d_map.size() >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
    shard.evict(data);
  }

  auto [mapIt, result] = data.d_map.try_emplace(key, std::move(newValue));

  if (result) {
    if (data.d_smallFIFO.full()) {
      shard.evictSmall(data, CacheShard::EvictionType::NeedRoomInFIFO);
    }
    data.d_smallFIFO.push_front(key);
    ++shard.d_entriesCount;
    return;
  }

  CacheValue& value = mapIt->second;
  /* was the existing entry a ghost ? */
  if (value.isGhost()) {
    value = std::move(newValue);
    if (data.d_mainFIFO.full()) {
      shard.evictMain(data, CacheShard::EvictionType::NeedRoomInFIFO);
    }
    data.d_mainFIFO.push_front(key);
    ++shard.d_entriesCount;
    return;
  }

  /* in case of collision, don't override the existing entry
     except if it has expired */
  bool wasExpired = value.validity <= newValue.added;

  if (!wasExpired && !cachedValueMatches(value, newValue.queryFlags, newValue.qname, newValue.qtype, newValue.qclass, newValue.receivedOverUDP, newValue.dnssecOK, newValue.subnet)) {
    ++d_insertCollisions;
    return;
  }

  /* if the existing entry had a longer TTD, keep it */
  if (newValue.validity <= value.validity) {
    return;
  }

  value = std::move(newValue);
}

void DNSDistPacketCache::insert(uint32_t key, const boost::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const PacketBuffer& response, bool receivedOverUDP, uint8_t rcode, boost::optional<uint32_t> tempFailureTTL)
{
  if (response.size() < sizeof(dnsheader) || response.size() > getMaximumEntrySize()) {
    return;
  }

  if (qtype == QType::AXFR || qtype == QType::IXFR) {
    return;
  }

  uint32_t minTTL{0};

  if (rcode == RCode::ServFail || rcode == RCode::Refused) {
    minTTL = tempFailureTTL == boost::none ? d_settings.d_tempFailureTTL : *tempFailureTTL;
    if (minTTL == 0) {
      return;
    }
  }
  else {
    bool seenAuthSOA = false;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    minTTL = getMinTTL(reinterpret_cast<const char*>(response.data()), response.size(), &seenAuthSOA);

    if (minTTL == std::numeric_limits<uint32_t>::max()) {
      /* no TTL found, we probably don't want to cache this
         unless it's an empty (no records) truncated answer,
         and we have been asked to cache these */
      if (d_settings.d_truncatedTTL == 0) {
        return;
      }
      dnsheader_aligned dh_aligned(response.data());
      if (dh_aligned->tc == 0) {
        return;
      }
      minTTL = d_settings.d_truncatedTTL;
    }

    if (rcode == RCode::NXDomain || (rcode == RCode::NoError && seenAuthSOA)) {
      minTTL = std::min(minTTL, d_settings.d_maxNegativeTTL);
    }
    else if (minTTL > d_settings.d_maxTTL) {
      minTTL = d_settings.d_maxTTL;
    }

    if (minTTL < d_settings.d_minTTL) {
      ++d_ttlTooShorts;
      return;
    }
  }

  const auto shardIndex = getShardIndex(key);
  const time_t now = time(nullptr);
  time_t newValidity = now + minTTL;
  CacheValue newValue;
  newValue.qname = qname;
  newValue.qtype = qtype;
  newValue.qclass = qclass;
  newValue.queryFlags = queryFlags;
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.receivedOverUDP = receivedOverUDP;
  newValue.dnssecOK = dnssecOK;
  newValue.value = response;
  newValue.subnet = subnet;

  auto& shard = d_shards.at(shardIndex);

  if (d_settings.d_deferrableInsertLock) {
    auto lock = shard.d_data.try_write_lock();
    if (!lock.owns_lock()) {
      ++d_deferredInserts;
      return;
    }
    insertLocked(shard, *lock, key, std::move(newValue));
  }
  else {
    auto lock = shard.d_data.write_lock();

    insertLocked(shard, *lock, key, std::move(newValue));
  }
}

void DNSDistPacketCache::handleHit(const CacheValue& value)
{
  ++d_hits;

  auto freq = value.freq.inner.load();
  while (freq < 3) {
    if (value.freq.inner.compare_exchange_weak(freq, static_cast<int8_t>(freq + 1U))) {
      break;
    }
  }
}

bool DNSDistPacketCache::get(DNSQuestion& dnsQuestion, uint16_t queryId, uint32_t* keyOut, boost::optional<Netmask>& subnet, bool dnssecOK, bool receivedOverUDP, uint32_t allowExpired, bool skipAging, bool truncatedOK, bool recordMiss)
{
  if (dnsQuestion.ids.qtype == QType::AXFR || dnsQuestion.ids.qtype == QType::IXFR) {
    ++d_misses;
    return false;
  }

  const auto& dnsQName = dnsQuestion.ids.qname.getStorage();
  uint32_t key = getKey(dnsQName, dnsQuestion.ids.qname.wirelength(), dnsQuestion.getData(), receivedOverUDP);
  if (keyOut != nullptr) {
    *keyOut = key;
  }

  if (d_settings.d_parseECS) {
    getClientSubnet(dnsQuestion.getData(), dnsQuestion.ids.qname.wirelength(), subnet);
  }

  uint32_t shardIndex = getShardIndex(key);
  time_t now = time(nullptr);
  time_t age{0};
  bool stale = false;
  auto& response = dnsQuestion.getMutableData();
  auto& shard = d_shards.at(shardIndex);
  {
    auto data = shard.d_data.try_read_lock();
    if (!data.owns_lock()) {
      ++d_deferredLookups;
      return false;
    }

    const auto& map = data->d_map;
    auto mapIt = map.find(key);
    if (mapIt == map.end() || mapIt->second.isGhost()) {
      if (recordMiss) {
        ++d_misses;
      }
      return false;
    }

    const CacheValue& value = mapIt->second;
    if (value.validity <= now) {
      if ((now - value.validity) >= static_cast<time_t>(allowExpired)) {
        if (recordMiss) {
          ++d_misses;
        }
        return false;
      }
      stale = true;
    }

    if (value.value.size() < sizeof(dnsheader)) {
      return false;
    }

    /* check for collision */
    if (!cachedValueMatches(value, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnsQuestion.ids.qname, dnsQuestion.ids.qtype, dnsQuestion.ids.qclass, receivedOverUDP, dnssecOK, subnet)) {
      ++d_lookupCollisions;
      return false;
    }

    if (!truncatedOK) {
      dnsheader_aligned dh_aligned(value.value.data());
      if (dh_aligned->tc != 0) {
        return false;
      }
    }

    response.resize(value.value.size());
    memcpy(&response.at(0), &queryId, sizeof(queryId));
    memcpy(&response.at(sizeof(queryId)), &value.value.at(sizeof(queryId)), sizeof(dnsheader) - sizeof(queryId));

    if (value.value.size() == sizeof(dnsheader)) {
      /* DNS header only, our work here is done */
      handleHit(value);
      return true;
    }

    const size_t dnsQNameLen = dnsQName.length();
    if (value.value.size() < (sizeof(dnsheader) + dnsQNameLen)) {
      return false;
    }

    memcpy(&response.at(sizeof(dnsheader)), dnsQName.c_str(), dnsQNameLen);
    if (value.value.size() > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(&response.at(sizeof(dnsheader) + dnsQNameLen), &value.value.at(sizeof(dnsheader) + dnsQNameLen), value.value.size() - (sizeof(dnsheader) + dnsQNameLen));
    }

    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_settings.d_staleTTL;
    }

    handleHit(value);
  }

  if (!d_settings.d_dontAge && !skipAging) {
    if (!stale) {
      // coverity[store_truncates_time_t]
      dnsheader_aligned dh_aligned(response.data());
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      ageDNSPacket(reinterpret_cast<char*>(response.data()), response.size(), age, dh_aligned);
    }
    else {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      editDNSPacketTTL(reinterpret_cast<char*>(response.data()), response.size(),
                       [staleTTL = d_settings.d_staleTTL](uint8_t /* section */, uint16_t /* class_ */, uint16_t /* type */, uint32_t /* ttl */) { return staleTTL; });
    }
  }

  return true;
}

size_t DNSDistPacketCache::removeViaFIFO(CacheShard& shard, CacheShard::ShardData& data, FIFOToExpungeFrom from, size_t& toRemove, const time_t now, bool onlyExpired)
{
  auto& map = data.d_map;
  auto& fifo = from == FIFOToExpungeFrom::SmallFIFO ? data.d_smallFIFO : data.d_mainFIFO;
  size_t removed = 0;

  for (auto fifoIt = fifo.rbegin(); toRemove > 0 && fifoIt != fifo.rend();) {
    auto mapIt = map.find(*fifoIt);
    if (mapIt == map.end()) {
      /* unfortunately we can only remove from the FIFO
         if we are looking at the last element */
      if (fifoIt == fifo.rbegin()) {
        fifo.pop_back();
        fifoIt = fifo.rbegin();
      }
      else {
        ++fifoIt;
      }
      continue;
    }

    const CacheValue& value = mapIt->second;
    if (!value.isGhost() && (!onlyExpired || value.validity <= now)) {
      map.erase(mapIt);
      --toRemove;
      --shard.d_entriesCount;
      ++removed;
      /* unfortunately we can only remove from the FIFO
         if we are looking at the last element */
      if (fifoIt == fifo.rbegin()) {
        fifo.pop_back();
        fifoIt = fifo.rbegin();
        continue;
      }
    }

    ++fifoIt;
  }

  return removed;
}

/* Remove expired entries, until the cache has at most
   upTo entries in it.
   If the cache has more than one shard, we will try hard
   to make sure that every shard has free space remaining.
*/
size_t DNSDistPacketCache::purgeExpired(size_t upTo, const time_t now)
{
  const size_t maxPerShard = upTo / d_settings.d_shardCount;

  size_t removed = 0;

  ++d_cleanupCount;

  for (auto& shard : d_shards) {
    if (shard.d_entriesCount <= maxPerShard) {
      continue;
    }
    auto data = shard.d_data.write_lock();
    size_t toRemove = shard.d_entriesCount - maxPerShard;

    removed += removeViaFIFO(shard, *data, FIFOToExpungeFrom::MainFIFO, toRemove, now, true);
    removed += removeViaFIFO(shard, *data, FIFOToExpungeFrom::SmallFIFO, toRemove, now, true);
  }

  return removed;
}

/* Remove all entries, keeping only upTo
   entries in the cache.
   If the cache has more than one shard, we will try hard
   to make sure that every shard has free space remaining.
*/
size_t DNSDistPacketCache::expunge(size_t upTo)
{
  const size_t maxPerShard = upTo / d_settings.d_shardCount;

  size_t removed = 0;

  for (auto& shard : d_shards) {
    if (shard.d_entriesCount <= maxPerShard) {
      continue;
    }
    auto data = shard.d_data.write_lock();

    size_t toRemove = shard.d_entriesCount - maxPerShard;
    removed += removeViaFIFO(shard, *data, FIFOToExpungeFrom::SmallFIFO, toRemove, 0, false);
    removed += removeViaFIFO(shard, *data, FIFOToExpungeFrom::MainFIFO, toRemove, 0, false);
  }

  return removed;
}

size_t DNSDistPacketCache::expungeByName(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
  size_t removed = 0;

  for (auto& shard : d_shards) {
    auto data = shard.d_data.write_lock();
    auto& map = data->d_map;
    std::set<KeyType> removedFromShard;

    for (auto it = map.begin(); it != map.end();) {
      const CacheValue& value = it->second;

      if (!value.isGhost() && (value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {
        removedFromShard.insert(it->first);
        it = map.erase(it);
        --shard.d_entriesCount;
        ++removed;
      }
      else {
        ++it;
      }
    }
    auto& smallFIFO = data->d_smallFIFO;
    for (auto smallIt = smallFIFO.begin(); !removedFromShard.empty() && smallIt != smallFIFO.end();) {
      if (removedFromShard.count(*smallIt) == 1) {
        removedFromShard.erase(*smallIt);
        smallIt = smallFIFO.erase(smallIt);
      }
      else {
        ++smallIt;
      }
    }
  }

  return removed;
}

bool DNSDistPacketCache::isFull()
{
  return (getSize() >= d_settings.d_maxEntries);
}

uint64_t DNSDistPacketCache::getSize()
{
  uint64_t count = 0;

  for (auto& shard : d_shards) {
    count += shard.d_entriesCount;
  }

  return count;
}

uint32_t DNSDistPacketCache::getMinTTL(const char* packet, uint16_t length, bool* seenNoDataSOA)
{
  return getDNSPacketMinTTL(packet, length, seenNoDataSOA);
}

uint32_t DNSDistPacketCache::getKey(const DNSName::string_t& qname, size_t qnameWireLength, const PacketBuffer& packet, bool receivedOverUDP)
{
  uint32_t result = 0;
  /* skip the query ID */
  if (packet.size() < sizeof(dnsheader)) {
    throw std::range_error("Computing packet cache key for an invalid packet size (" + std::to_string(packet.size()) + ")");
  }

  result = burtle(&packet.at(2), sizeof(dnsheader) - 2, result);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  result = burtleCI(reinterpret_cast<const unsigned char*>(qname.c_str()), qname.length(), result);
  if (packet.size() < sizeof(dnsheader) + qnameWireLength) {
    throw std::range_error("Computing packet cache key for an invalid packet (" + std::to_string(packet.size()) + " < " + std::to_string(sizeof(dnsheader) + qnameWireLength) + ")");
  }
  if (packet.size() > ((sizeof(dnsheader) + qnameWireLength))) {
    if (!d_settings.d_optionsToSkip.empty()) {
      /* skip EDNS options if any */
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      result = PacketCache::hashAfterQname(std::string_view(reinterpret_cast<const char*>(packet.data()), packet.size()), result, sizeof(dnsheader) + qnameWireLength, d_settings.d_optionsToSkip);
    }
    else {
      result = burtle(&packet.at(sizeof(dnsheader) + qnameWireLength), packet.size() - (sizeof(dnsheader) + qnameWireLength), result);
    }
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  result = burtle(reinterpret_cast<const unsigned char*>(&receivedOverUDP), sizeof(receivedOverUDP), result);
  return result;
}

uint32_t DNSDistPacketCache::getShardIndex(uint32_t key) const
{
  return key % d_settings.d_shardCount;
}

string DNSDistPacketCache::toString()
{
  return std::to_string(getSize()) + "/" + std::to_string(d_settings.d_maxEntries);
}

uint64_t DNSDistPacketCache::getEntriesCount()
{
  return getSize();
}

uint64_t DNSDistPacketCache::dump(int fileDesc, bool rawResponse)
{
  auto fileDescDuplicated = dup(fileDesc);
  if (fileDescDuplicated < 0) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(fileDescDuplicated, "w"));
  if (filePtr == nullptr) {
    return 0;
  }

  fprintf(filePtr.get(), "; dnsdist's packet cache dump follows\n;\n");

  uint64_t count = 0;
  time_t now = time(nullptr);
  for (auto& shard : d_shards) {
    auto data = shard.d_data.read_lock();
    const auto& map = data->d_map;

    for (const auto& entry : map) {
      const CacheValue& value = entry.second;
      if (value.isGhost()) {
        continue;
      }

      count++;

      try {
        uint8_t rcode = 0;
        if (value.value.size() >= sizeof(dnsheader)) {
          dnsheader dnsHeader{};
          memcpy(&dnsHeader, value.value.data(), sizeof(dnsheader));
          rcode = dnsHeader.rcode;
        }

        fprintf(filePtr.get(), "%s %" PRId64 " %s %s ; ecs %s, rcode %" PRIu8 ", key %" PRIu32 ", length %" PRIu16 ", received over UDP %d, added %" PRId64 ", dnssecOK %d, raw query flags %" PRIu16, value.qname.toString().c_str(), static_cast<int64_t>(value.validity - now), QClass(value.qclass).toString().c_str(), QType(value.qtype).toString().c_str(), value.subnet ? value.subnet.get().toString().c_str() : "empty", rcode, entry.first, static_cast<uint16_t>(value.value.size()), value.receivedOverUDP ? 1 : 0, static_cast<int64_t>(value.added), value.dnssecOK ? 1 : 0, value.queryFlags);

        if (rawResponse) {
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          auto rawDataResponse = Base64Encode(std::string_view(reinterpret_cast<const char*>(value.value.data()), value.value.size()));
          fprintf(filePtr.get(), ", base64response %s", rawDataResponse.c_str());
        }
        fprintf(filePtr.get(), "\n");
      }
      catch (...) {
        fprintf(filePtr.get(), "; error printing '%s'\n", value.qname.empty() ? "EMPTY" : value.qname.toString().c_str());
      }
    }
  }

  return count;
}

std::set<DNSName> DNSDistPacketCache::getDomainsContainingRecords(const ComboAddress& addr)
{
  std::set<DNSName> domains;

  for (auto& shard : d_shards) {
    auto data = shard.d_data.read_lock();
    const auto& map = data->d_map;

    for (const auto& entry : map) {
      const CacheValue& value = entry.second;

      try {
        if (value.isGhost() || value.value.size() < sizeof(dnsheader)) {
          continue;
        }

        dnsheader_aligned dnsHeader(value.value.data());
        if (dnsHeader->rcode != RCode::NoError || (dnsHeader->ancount == 0 && dnsHeader->nscount == 0 && dnsHeader->arcount == 0)) {
          continue;
        }

        bool found = false;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        bool valid = visitDNSPacket(std::string_view(reinterpret_cast<const char*>(value.value.data()), value.value.size()), [addr, &found](uint8_t /* section */, uint16_t qclass, uint16_t qtype, uint32_t /* ttl */, uint16_t rdatalength, const char* rdata) {
          if (qtype == QType::A && qclass == QClass::IN && addr.isIPv4() && rdatalength == 4 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin4.sin_family = AF_INET;
            memcpy(&parsed.sin4.sin_addr.s_addr, rdata, rdatalength);
            if (parsed == addr) {
              found = true;
              return true;
            }
          }
          else if (qtype == QType::AAAA && qclass == QClass::IN && addr.isIPv6() && rdatalength == 16 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin6.sin6_family = AF_INET6;
            memcpy(&parsed.sin6.sin6_addr.s6_addr, rdata, rdatalength);
            if (parsed == addr) {
              found = true;
              return true;
            }
          }

          return false;
        });

        if (valid && found) {
          domains.insert(value.qname);
        }
      }
      catch (...) {
        continue;
      }
    }
  }

  return domains;
}

std::set<ComboAddress> DNSDistPacketCache::getRecordsForDomain(const DNSName& domain)
{
  std::set<ComboAddress> addresses;

  for (auto& shard : d_shards) {
    auto data = shard.d_data.read_lock();
    const auto& map = data->d_map;

    for (const auto& entry : map) {
      const CacheValue& value = entry.second;

      try {
        if (value.isGhost() || value.qname != domain) {
          continue;
        }

        if (value.value.size() < sizeof(dnsheader)) {
          continue;
        }

        dnsheader_aligned dnsHeader(value.value.data());
        if (dnsHeader->rcode != RCode::NoError || (dnsHeader->ancount == 0 && dnsHeader->nscount == 0 && dnsHeader->arcount == 0)) {
          continue;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        visitDNSPacket(std::string_view(reinterpret_cast<const char*>(value.value.data()), value.value.size()), [&addresses](uint8_t /* section */, uint16_t qclass, uint16_t qtype, uint32_t /* ttl */, uint16_t rdatalength, const char* rdata) {
          if (qtype == QType::A && qclass == QClass::IN && rdatalength == 4 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin4.sin_family = AF_INET;
            memcpy(&parsed.sin4.sin_addr.s_addr, rdata, rdatalength);
            addresses.insert(parsed);
          }
          else if (qtype == QType::AAAA && qclass == QClass::IN && rdatalength == 16 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin6.sin6_family = AF_INET6;
            memcpy(&parsed.sin6.sin6_addr.s6_addr, rdata, rdatalength);
            addresses.insert(parsed);
          }

          return false;
        });
      }
      catch (...) {
        continue;
      }
    }
  }

  return addresses;
}

uint64_t DNSDistPacketCache::getSmallFIFOSize()
{
  uint64_t count = 0;
  for (auto& shard : d_shards) {
    count += shard.d_data.read_lock()->d_smallFIFO.size();
  }
  return count;
}

uint64_t DNSDistPacketCache::getMainFIFOSize()
{
  uint64_t count = 0;
  for (auto& shard : d_shards) {
    count += shard.d_data.read_lock()->d_mainFIFO.size();
  }
  return count;
}

uint64_t DNSDistPacketCache::getGhostFIFOSize()
{
  uint64_t count = 0;
  for (auto& shard : d_shards) {
    count += shard.d_data.read_lock()->d_ghostFIFO.size();
  }
  return count;
}
