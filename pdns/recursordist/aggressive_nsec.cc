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

#include "aggressive_nsec.hh"

std::unique_ptr<AggressiveNSECZoneIndex> g_aggressiveNSECCache{nullptr};

void AggressiveNSECZoneIndex::insertNSECZoneInfo(const DNSName& zone)
{
  cerr<<"adding info for nsec zone "<<zone<<endl;
  WriteLock wl(d_lock);
  AggressiveNSECZoneIndex::Entry entry{zone, std::string(), 0, false};
  d_zones.add(zone, std::move(entry));
}

void AggressiveNSECZoneIndex::insertNSEC3ZoneInfo(const DNSName& zone, const std::string& salt, uint16_t iterations)
{
  cerr<<"adding info for nsec3 zone "<<zone<<endl;
  WriteLock wl(d_lock);
  AggressiveNSECZoneIndex::Entry entry{zone, salt, iterations, true};
  d_zones.add(zone, std::move(entry));
}

void AggressiveNSECZoneIndex::removeZoneInfo(const DNSName& zone)
{
  cerr<<"removing info for zone "<<zone<<endl;
  WriteLock wl(d_lock);
  d_zones.remove(zone);
}

bool AggressiveNSECZoneIndex::getBestZoneInfo(DNSName& lookup, bool& nsec3, std::string& salt, uint16_t& iterations)
{
  cerr<<"looking for lookup "<<lookup<<endl;
  ReadLock rl(d_lock);
  const auto entry = d_zones.lookup(lookup);
  if (entry == nullptr) {
    cerr<<"nothing for you"<<endl;
    return false;
  }
  lookup = entry->d_zone;
  nsec3 = entry->d_nsec3;
  if (nsec3) {
    salt = entry->d_salt;
    iterations = entry->d_iterations;
  }
  cerr<<"found "<<lookup<<endl;
  return true;
}
