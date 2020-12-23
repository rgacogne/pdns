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

#include "dnsname.hh"
#include "lock.hh"

class AggressiveNSECZoneIndex
{
public:
  void insertNSECZoneInfo(const DNSName& zone);
  void insertNSEC3ZoneInfo(const DNSName& zone, const std::string& salt, uint16_t iterations);
  void removeZoneInfo(const DNSName& zone);
  bool getBestZoneInfo(DNSName& lookup, bool& nsec3, std::string& salt, uint16_t& iterations);

private:
  struct Entry
  {
    Entry()
    {
    }

    Entry(const DNSName& zone, const std::string& salt, uint16_t iterations, bool nsec3): d_zone(zone), d_salt(salt), d_iterations(iterations), d_nsec3(nsec3)
    {
    }

    DNSName d_zone;
    std::string d_salt;
    uint16_t d_iterations{0};
    bool d_nsec3{false};
  };

  SuffixMatchTree<Entry> d_zones;
  ReadWriteLock d_lock;
};


extern std::unique_ptr<AggressiveNSECZoneIndex> g_aggressiveNSECCache;
