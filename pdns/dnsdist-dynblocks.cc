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

#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"

static boost::circular_buffer<DynBlockStatsEntry > s_dynblockStatsEntries;
static std::mutex s_dynblockStatsEntriesMutex;

size_t g_dynBlockCleaningDelay{0};
size_t g_dynBlockCountersRefreshDelay{0};
std::map<std::string, std::vector<std::pair<Netmask, uint64_t> > > g_topDynBlockNMGEntries;
std::map<std::string, vector<std::pair<DNSName, uint64_t> > > g_topDynBlockSMTEntries;

void insertDynBlockNMGEntry(const std::string& tag, const Netmask& nm)
{
  std::lock_guard<std::mutex> lock(s_dynblockStatsEntriesMutex);
  auto& lastBucket = s_dynblockStatsEntries.back();
  auto statEntry = lastBucket.d_NMGEntries[tag].find(nm);
  /* if it doesn't exist yet, create it and set the previous counter to 0
     otherwise both the previous and current counter might be > 0 */
  if (statEntry == lastBucket.d_NMGEntries[tag].end()) {
    lastBucket.d_NMGEntries[tag][nm].d_previousCounter = 0;
  }
}

void insertDynBlockSMTEntry(const std::string& tag, const DNSName& name)
{
  std::lock_guard<std::mutex> lock(s_dynblockStatsEntriesMutex);
  auto& lastBucket = s_dynblockStatsEntries.back();
  auto statEntry = lastBucket.d_SMTEntries[tag].find(name);
//    statEntry->second.d_previousCounter = previous;
  /* if it doesn't exist yet, create it and set the previous counter to 0
     otherwise both the previous and current counter might be > 0 */
  if (statEntry == lastBucket.d_SMTEntries[tag].end()) {
    lastBucket.d_SMTEntries[tag][name].d_previousCounter = 0;
  }
}

void purgeExpiredDynBlockNMGEntries(GlobalStateHolder<NetmaskTree<DynBlock>>& dynblockNMG)
{
  NetmaskTree<DynBlock> fresh;
  const auto full = dynblockNMG.getCopy();
  struct timespec now;
  gettime(&now);

  for(const auto& entry: full) {
    if (now < entry->second.until) {
      fresh.insert(entry->first).second = entry->second;
    } else {
      std::lock_guard<std::mutex> lock(s_dynblockStatsEntriesMutex);
      auto& lastBucket = s_dynblockStatsEntries.back();
      auto statEntry = lastBucket.d_NMGEntries[entry->second.reason].find(entry->first);
      if (statEntry != lastBucket.d_NMGEntries[entry->second.reason].end()) {
        statEntry->second.d_counter += entry->second.blocks - statEntry->second.d_previousCounter;
      } else {
        lastBucket.d_NMGEntries[entry->second.reason][entry->first].d_counter = entry->second.blocks;
      }
    }
  }

  dynblockNMG.setState(fresh);
}

void purgeExpiredDynBlockSMTEntries(GlobalStateHolder<SuffixMatchTree<DynBlock>>& dynblockSMT)
{
  SuffixMatchTree<DynBlock> fresh;
  const auto full = dynblockSMT.getCopy();
  struct timespec now;
  gettime(&now);

  full.visit([now, &fresh](const SuffixMatchTree<DynBlock>& node) {
    if (now < node.d_value.until) {
      fresh.add(node.d_value.domain, node.d_value);
    } else {
      std::lock_guard<std::mutex> lock(s_dynblockStatsEntriesMutex);
      auto& lastBucket = s_dynblockStatsEntries.back();
      auto statEntry = lastBucket.d_SMTEntries[node.d_value.reason].find(node.d_value.domain);
      if (statEntry != lastBucket.d_SMTEntries[node.d_value.reason].end()) {
        statEntry->second.d_counter += node.d_value.blocks - statEntry->second.d_previousCounter;
      } else {
        lastBucket.d_SMTEntries[node.d_value.reason][node.d_value.domain].d_counter = node.d_value.blocks;
      }
    }
  });

  dynblockSMT.setState(fresh);
}

std::map<std::string, std::vector<std::pair<Netmask, uint64_t> > > getTopDynBlockNMGEntries(GlobalStateHolder<NetmaskTree<DynBlock>>& dynblockNMG, size_t top)
{
  std::map<std::string, std::map<Netmask, uint64_t> > results;

  std::lock_guard<std::mutex> lock(s_dynblockStatsEntriesMutex);

  for (const auto& bucket: s_dynblockStatsEntries) {
    for (const auto& tagEntries: bucket.d_NMGEntries) {
      for (const auto& clientEntry: tagEntries.second) {
        results[tagEntries.first][clientEntry.first] += clientEntry.second.d_counter;
      }
    }
  }

  const auto& lastBucket = s_dynblockStatsEntries.back();
  const auto copy = g_dynblockNMG.getCopy();
  for(const auto& entry: copy) {
    uint64_t previous = 0;
    const auto& tag = lastBucket.d_NMGEntries.find(entry->second.reason);
    if (tag != lastBucket.d_NMGEntries.cend()) {
      const auto& client = tag->second.find(entry->first);
      if (client != tag->second.cend()) {
        previous = client->second.d_previousCounter;
      }
    }

    results[entry->second.reason][entry->first] += (entry->second.blocks - previous);
  }

  std::map<std::string, std::vector<std::pair<Netmask, uint64_t> > > tops;
  for (auto& tag : results) {
    auto& vect = tops[tag.first];

    for (const auto& client : tag.second) {
      vect.push_back({ client.first, client.second });
    }

    auto toSort = std::min(vect.size(), top);
    partial_sort(vect.begin(), vect.begin() + toSort, vect.end(), [](const std::pair<Netmask, uint64_t>& a, const std::pair<Netmask, uint64_t>& b) {
        return (b.first < a.first);
      });

    tops[tag.first].reserve(toSort);
    std::copy(vect.begin(), vect.begin() + toSort, tops[tag.first].begin());
  }

  return tops;
}

std::map<std::string, vector<std::pair<DNSName, uint64_t> > > getTopDynBlockSMTEntries(GlobalStateHolder<SuffixMatchTree<DynBlock>>& dynblockSMT, size_t top)
{
  std::map<std::string, std::unordered_map<DNSName, uint64_t> > results;

  std::lock_guard<std::mutex> lock(s_dynblockStatsEntriesMutex);

  for (const auto& bucket: s_dynblockStatsEntries) {
    for (const auto& tagEntries: bucket.d_SMTEntries) {
      for (const auto& clientEntry: tagEntries.second) {
        results[tagEntries.first][clientEntry.first] += clientEntry.second.d_counter;
      }
    }
  }

  const auto& lastBucket = s_dynblockStatsEntries.back();
  const auto copy = g_dynblockSMT.getCopy();

  copy.visit([lastBucket, &results](const SuffixMatchTree<DynBlock>& node) {
    uint64_t previous = 0;
    const auto& tag = lastBucket.d_SMTEntries.find(node.d_value.reason);
    if (tag != lastBucket.d_SMTEntries.cend()) {
      const auto& domain = tag->second.find(node.d_value.domain);
      if (domain != tag->second.cend()) {
        previous = domain->second.d_previousCounter;
      }
    }
    results[node.d_value.reason][node.d_value.domain] += (node.d_value.blocks - previous);

  });

  std::map<std::string, std::vector<std::pair<DNSName, uint64_t> > > tops;
  for (auto& tag : results) {
    auto& vect = tops[tag.first];

    for (const auto& client : tag.second) {
      vect.push_back({ client.first, client.second });
    }

    auto toSort = std::min(vect.size(), top);
    partial_sort(vect.begin(), vect.begin() + toSort, vect.end(), [](const std::pair<DNSName, uint64_t>& a, const std::pair<DNSName, uint64_t>& b) {
        return (b.first < a.first);
      });

    tops[tag.first].reserve(toSort);
    std::copy(vect.begin(), vect.begin() + toSort, tops[tag.first].begin());
  }

  return tops;
}
