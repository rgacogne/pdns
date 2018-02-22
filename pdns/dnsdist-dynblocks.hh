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

#include <unordered_set>

class DynBlockStatsTimeEntry
{
public:
  uint64_t d_previousCounter{0};
  uint64_t d_counter{0};
};

class DynBlockStatsEntry
{
public:
  void fill(std::unordered_map<std::string, std::map<Netmask, DynBlockStatsTimeEntry> >& map)
  {
    for (const auto& entry : d_NMGEntries) {
      const auto& reason = entry.first;

      for (const auto& value : entry.second) {
        map[reason][value.first].d_counter += value.second.d_counter - value.second.d_previousCounter;
      }
    }
  }

  std::unordered_map<std::string, std::map<Netmask, DynBlockStatsTimeEntry> > d_NMGEntries;
  std::unordered_map<std::string, std::map<DNSName, DynBlockStatsTimeEntry> > d_SMTEntries;
};

void purgeExpiredDynBlockNMGEntries(GlobalStateHolder<NetmaskTree<DynBlock>>& dynblockNMG);
void purgeExpiredDynBlockSMTEntries(GlobalStateHolder<SuffixMatchTree<DynBlock>>& dynblockSMT);

std::map<std::string, std::vector<std::pair<Netmask, uint64_t> > > getTopDynBlockNMGEntries(GlobalStateHolder<NetmaskTree<DynBlock>>& dynblockNMG, size_t top);
