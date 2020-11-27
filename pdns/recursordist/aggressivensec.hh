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

#include <mutex>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>

#include "dns.hh"
#include "dnsrecords.hh"

class AggressiveNSECZoneData
{
public:
  void addSOA(const DNSRecord& soa, const std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures);
  void addNSEC(const DNSName& name, time_t ttd, const DNSRecord& record, const std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures);

  bool getNSEC(const DNSName& name, uint16_t qtype, time_t now, DNSRecord& nsec, std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures, bool& exact);

//oprivate:
  struct SequencedTag {};
  struct OrderedTag {};

  struct CacheEntry
  {
    std::vector<std::shared_ptr<RRSIGRecordContent>> d_signatures;
    DNSRecord d_record;
    DNSName d_name;
    time_t d_ttd{0};
  };

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<tag<OrderedTag>,
                               member<CacheEntry,DNSName,&CacheEntry::d_name>,
                               CanonDNSNameCompare
                               >,
                sequenced<tag<SequencedTag> >
                >
    > cache_t;

  std::mutex d_lock;
  cache_t d_records;
  DNSRecord d_soa;
  std::vector<std::shared_ptr<RRSIGRecordContent>> d_soaSignatures;
  std::string d_salt;
  uint16_t d_iterations{0};
  bool d_nsec3{false};
};
  
