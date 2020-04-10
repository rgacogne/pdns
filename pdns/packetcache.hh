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
#include "ednsoptions.hh"
#include "misc.hh"
#include "iputils.hh"
#include "views.hh"

class PacketCache : public boost::noncopyable
{
public:

  /* hash the packet from the provided position, which should point right after the qname. This skips:
     - the query ID ;
     - EDNS Cookie options, if any ;
     - EDNS Client Subnet options, if any and skipECS is true.
  */
  static uint32_t hashAfterQname(const string_view& packet, uint32_t currentHash, size_t pos, bool skipECS, bool skipCookies)
  {
    const size_t packetSize = packet.size();
    assert(packetSize >= sizeof(dnsheader));

    /* we need at least 2 (QTYPE) + 2 (QCLASS)

       + OPT root label (1), type (2), class (2) and ttl (4)
       + the OPT RR rdlen (2)
       = 15
    */
    const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(packet.data());
    if (ntohs(dh->qdcount) != 1 || ntohs(dh->ancount) != 0 || ntohs(dh->nscount) != 0 || ntohs(dh->arcount) != 1 || (pos + 15) >= packetSize) {
      if (packetSize > pos) {
        currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
      }
      return currentHash;
    }

    /* we hash everything except the rdata length of the OPT record, which will not match on different padding sizes, for example */
    currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), 13, currentHash);

    /* skip the qtype (2), qclass (2) */
    /* root label (1), type (2), class (2) and ttl (4) */
    /* already hashed above */
    pos += 13;

    const uint16_t rdLen = (static_cast<uint16_t>(static_cast<uint8_t>(packet.at(pos))) * 256) + static_cast<uint8_t>(packet.at(pos + 1));
    /* skip the rd length */
    pos += 2;

    if (rdLen > (packetSize - pos)) {
      if (pos < packetSize) {
        currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
      }
      return currentHash;
    }

    uint16_t rdataRead = 0;
    uint16_t optionCode;
    uint16_t optionLen;
    while (pos < packetSize && rdataRead < rdLen && getNextEDNSOption(&packet.at(pos), rdLen - rdataRead, optionCode, optionLen)) {
      if (optionLen > (rdLen - rdataRead - 4)) {
        if (packetSize > pos) {
          currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
        }
        return currentHash;
      }

      bool skip = false;
      if (optionCode == EDNSOptionCode::PADDING) {
        skip = true;
      }
      else if (optionCode == EDNSOptionCode::COOKIE && skipCookies) {
        skip = true;
      }
      else if (optionCode == EDNSOptionCode::ECS) {
        if (skipECS) {
          skip = true;
        }
      }

      if (!skip) {
        /* hash the option code, length and content */
        currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), 4 + optionLen, currentHash);
      }
      else {
        /* hash the option code (we care about the option being present) but not the length,
           except for ECS, where a zero-length source has a special meaning */
        if (optionCode == EDNSOptionCode::ECS) {
          currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), 4, currentHash);
        }
        else {
          currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), 2, currentHash);
        }
      }

      pos += 4 + optionLen;
      rdataRead += 4 + optionLen;
    }

    if (pos < packetSize) {
      currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
    }

    return currentHash;
  }

  static uint32_t hashHeaderAndQName(const std::string& packet, size_t& pos)
  {
    uint32_t currentHash = 0;
    const size_t packetSize = packet.size();
    assert(packetSize >= sizeof(dnsheader));
    currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(2)), sizeof(dnsheader) - 2, currentHash); // rest of dnsheader, skip id
    pos = sizeof(dnsheader);

    for (; pos < packetSize; ) {
      const unsigned char labelLen = static_cast<unsigned char>(packet.at(pos));
      currentHash = burtle(&labelLen, 1, currentHash);
      ++pos;
      if (labelLen == 0) {
        break;
      }

      for (size_t idx = 0; idx < labelLen && pos < packetSize; ++idx, ++pos) {
        const unsigned char l = dns_tolower(packet.at(pos));
        currentHash = burtle(&l, 1, currentHash);
      }
    }

    return currentHash;
  }

  /* hash the packet from the beginning, including the qname. This skips:
     - the query ID ;
     - EDNS Cookie options, if any ;
     - EDNS Client Subnet options, if any and skipECS is true.
  */
  static uint32_t canHashPacket(const std::string& packet, bool skipECS)
  {
    size_t pos = 0;
    uint32_t currentHash = hashHeaderAndQName(packet, pos);
    size_t packetSize = packet.size();

    if (pos >= packetSize) {
      return currentHash;
    }

    return hashAfterQname(packet, currentHash, pos, skipECS, true);
  }

  static bool queryHeaderMatches(const std::string& cachedQuery, const std::string& query)
  {
    const size_t querySize = query.size();
    const size_t cachedQuerySize = cachedQuery.size();
    if (querySize < sizeof(dnsheader) || cachedQuerySize < sizeof(dnsheader)) {
      return false;
    }

    return (cachedQuery.compare(/* skip the ID */ 2, sizeof(dnsheader) - 2, query, 2, sizeof(dnsheader) - 2) == 0);
  }

  static bool queryMatches(const std::string& cachedQuery, const std::string& query, const DNSName& qname, const std::unordered_set<uint16_t>& optionsToIgnore)
  {
    /* note that the two queries might have different sizes because of different padding, or different cookie sizes */
    const size_t querySize = query.size();
    const size_t cachedQuerySize = cachedQuery.size();

    if (!queryHeaderMatches(cachedQuery, query)) {

      return false;
    }

    size_t pos = sizeof(dnsheader) + qname.wirelength();

    /* we need at least 2 (QTYPE) + 2 (QCLASS)
       + OPT root label (1), type (2), class (2) and ttl (4)
       + the OPT RR rdlen (2)
       = 15
    */
    const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(query.data());
    if (ntohs(dh->qdcount) != 1 || ntohs(dh->ancount) != 0 || ntohs(dh->nscount) != 0 || ntohs(dh->arcount) != 1 || (pos + 15) >= querySize || (pos + 15) >= cachedQuerySize || optionsToIgnore.empty()) {
      if (cachedQuerySize != querySize) {
        return false;
      }
      return cachedQuery.compare(pos, cachedQuerySize - pos, query, pos, querySize - pos) == 0;
    }

    /* compare up to the first option, if any, except for the rdata length, which
       will differ on different EDNS Padding sizes, for example */
    if (cachedQuery.compare(pos, 13, query, pos, 13) != 0) {
      return false;
    }

    /* skip the qtype (2), qclass (2) */
    /* root label (1), type (2), class (2) and ttl (4) */
    /* already compared above */
    pos += 13;

    const uint16_t rdLen = (static_cast<uint16_t>(static_cast<uint8_t>(query.at(pos))) * 256) + static_cast<uint8_t>(query.at(pos + 1));
    const uint16_t cachedRDLen = (static_cast<uint16_t>(static_cast<uint8_t>(cachedQuery.at(pos))) * 256) + static_cast<uint8_t>(cachedQuery.at(pos + 1));
    /* skip the rd length */
    pos += sizeof(uint16_t);

    if (rdLen > (querySize - pos) || cachedRDLen > (cachedQuerySize - pos)) {
      /* something is wrong, let's just compare everything */
      if (cachedQuerySize != querySize) {
        return false;
      }
      return cachedQuery.compare(pos, cachedQuerySize - pos, query, pos, querySize - pos) == 0;
    }

    /* from now on, the positions in the query and the cached query might be different because of
       different padding or cookie sizes.
       We stop as soon as the option code differs since the hashes would have been different in that case.
    */
    size_t cachedPos = pos;
    uint16_t rdataRead = 0;
    uint16_t cachedRDataRead = 0;
    uint16_t optionCode;
    uint16_t optionLen;
    uint16_t cachedOptionCode;
    uint16_t cachedOptionLen;

    while (pos < querySize && rdataRead < rdLen && cachedPos < cachedQuerySize && cachedRDataRead < cachedRDLen) {
      if (!getNextEDNSOption(&query.at(pos), rdLen - rdataRead, optionCode, optionLen)) {
        break;
      }

      if (optionLen > (rdLen - rdataRead)) {
        /* invalid option length, stop right there */
        if ((cachedQuerySize - cachedPos) != (querySize - pos)) {
         return false;
        }
        return cachedQuery.compare(cachedPos, cachedQuerySize - cachedPos, query, pos, querySize - pos) == 0;
      }

      if (!getNextEDNSOption(&cachedQuery.at(cachedPos), cachedRDLen - cachedRDataRead, cachedOptionCode, cachedOptionLen)) {
        break;
      }

      if (cachedOptionLen > (cachedRDLen - cachedRDataRead)) {
        /* invalid option length, stop right there */
        if ((cachedQuerySize - cachedPos) != (querySize - pos)) {
          return false;
        }
        return cachedQuery.compare(cachedPos, cachedQuerySize - cachedPos, query, pos, querySize - pos) == 0;
        break;
      }

      /* compare the option code */
      if (optionCode != cachedOptionCode) {
        return false;
      }

      pos += 2;
      rdataRead += 2;
      cachedPos += 2;
      cachedRDataRead += 2;

      if (optionsToIgnore.count(optionCode) == 0) {
        /* compare the option length and the content */
        if (cachedQuery.compare(cachedPos, 2 + cachedOptionLen, query, pos, 2 + optionLen) != 0) {
          return false;
        }
      }
      else if (optionCode == EDNSOptionCode::ECS) {
        /* for ECS the presence of a source of zero length has a special meaning, so let's compare the length
           even if we don't compare the content */
        if (cachedQuery.compare(cachedPos, 2, query, pos, 2) != 0) {
          return false;
        }
      }

      pos += 2 + optionLen;
      cachedPos += 2 + cachedOptionLen;
      rdataRead += 2 + optionLen;
      cachedRDataRead += 2 + cachedOptionLen;
    }

    if (pos >= querySize && cachedPos >= cachedQuerySize) {
        return true;
    }

    if ((cachedQuerySize - cachedPos) != (querySize - pos)) {
      return false;
    }

    return cachedQuery.compare(cachedPos, cachedQuerySize - cachedPos, query, pos, querySize - pos) == 0;
  }

};
