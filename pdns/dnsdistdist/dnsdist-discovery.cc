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

#include "dnsdist-discovery.hh"
#include "dnsdist.hh"
#include "dnsparser.hh"
#include "dolog.hh"
#include "sstuff.hh"

namespace dnsdist {

struct DesignatedResolvers
{
  DNSName target;
  std::set<SvcParam> params;
  std::vector<ComboAddress> hints;
};

static bool parseSVCParams(const std::string& answer, std::map<uint16_t, DesignatedResolvers>& resolvers)
{
  if (answer.size() <= sizeof(struct dnsheader)) {
    throw std::runtime_error("Looking for SVC records in a packet smaller than a DNS header");
  }

  std::map<DNSName, std::vector<ComboAddress>> hints;
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(answer.data());
  PacketReader pr(answer);
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);

  DNSName rrname;
  uint16_t rrtype;
  uint16_t rrclass;

  size_t idx = 0;
  /* consume qd */
  for(; idx < qdcount; idx++) {
    rrname = pr.getName();
    rrtype = pr.get16BitInt();
    rrclass = pr.get16BitInt();
    (void) rrtype;
    (void) rrclass;
  }

  /* parse AN */
  for (idx = 0; idx < ancount; idx++) {
    string blob;
    struct dnsrecordheader ah;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type == QType::SVCB) {
      auto prio = pr.get16BitInt();
      auto target = pr.getName();
      std::set<SvcParam> params;

      if (prio != 0) {
        pr.xfrSvcParamKeyVals(params);
      }

      resolvers[prio] = { std::move(target), std::move(params), {} };
    }
    else {
      pr.xfrBlob(blob);
    }
  }

  /* parse NS */
  for (idx = 0; idx < nscount; idx++) {
    string blob;
    struct dnsrecordheader ah;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pr.xfrBlob(blob);
  }

  /* parse additional for hints */
  for (idx = 0; idx < arcount; idx++) {
    string blob;
    struct dnsrecordheader ah;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type == QType::A) {
      ComboAddress addr;
      pr.xfrCAWithoutPort(4, addr);
      hints[rrname].push_back(addr);
    }
    else if (ah.d_type == QType::AAAA) {
      ComboAddress addr;
      pr.xfrCAWithoutPort(6, addr);
      hints[rrname].push_back(addr);
    }
    else {
      pr.xfrBlob(blob);
    }
  }

  for (auto& resolver : resolvers) {
    auto hint = hints.find(resolver.second.target);
    if (hint != hints.end()) {
      resolver.second.hints = hint->second;
    }
  }

  return !resolvers.empty();
}

bool discoverBackendUpgrade(const ComboAddress& addr, unsigned int timeout)
{
  try {
    const DNSName specialUseDomainName("_dns.resolver.arpa.");

    std::vector<uint8_t> packet;
    DNSPacketWriter pw(packet, specialUseDomainName, QType::SVCB);
    pw.getHeader()->id = getRandomDNSID();
    pw.getHeader()->rd = 1;
    pw.addOpt(4096, 0, 0);

    Socket sock(addr.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    sock.connect(addr);
    sock.send(string(packet.begin(), packet.end()));

    string reply;
    int ret = waitForData(sock.getHandle(), timeout, 0);
    if (ret < 0) {
      if (g_verbose) {
        warnlog("Error while waiting for the ADD upgrade response from backend %s: %d", addr.toString(), ret);
      }
      return false;
    }
    else if (ret == 0) {
      if (g_verbose) {
        warnlog("Timeout while waiting for the ADD upgrade response from backend %s", addr.toString());
      }
      return false;
    }

    try {
      sock.read(reply);
    }
    catch(const std::exception& e) {
      if (g_verbose) {
        warnlog("Error while reading for the ADD upgrade response from backend %s: %s", addr.toString(), e.what());
      }
      return false;
    }

    if (reply.size() <= sizeof(struct dnsheader)) {
      if (g_verbose) {
        warnlog("Too short answer of size %d received from the backend %s", reply.size(), addr.toString());
      }
      return false;
    }

    struct dnsheader d;
    memcpy(&d, reply.c_str(), sizeof(d));
    if (d.id != pw.getHeader()->id) {
      if (g_verbose) {
        warnlog("Invalid ID (%d / %d) received from the backend %s", d.id, pw.getHeader()->id, addr.toString());
      }
      return false;
    }

    if (d.rcode != RCode::NoError) {
      if (g_verbose) {
        warnlog("Response code '%s' received from the backend %s for '%s'", RCode::to_s(d.rcode), addr.toString(), specialUseDomainName);
      }

      return false;
    }

    if (ntohs(d.qdcount) != 1) {
      if (g_verbose) {
        warnlog("Invalid answer (qdcount %d) received from the backend %s", ntohs(d.qdcount), addr.toString());
      }
      return false;
    }

    uint16_t receivedType;
    uint16_t receivedClass;
    DNSName receivedName(reply.c_str(), reply.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != specialUseDomainName || receivedType != QType::SVCB || receivedClass != QClass::IN) {
      if (g_verbose) {
        warnlog("Invalid answer, either the qname (%s / %s), qtype (%s / %s) or qclass (%s / %s) does not match, received from the backend %s", receivedName, specialUseDomainName, QType(receivedType).toString(), QType(QType::SVCB).toString(), QClass(receivedClass).toString(), QClass::IN.toString(), addr.toString());
      }
      return false;
    }

    std::map<uint16_t, DesignatedResolvers> resolvers;

    if (!parseSVCParams(reply, resolvers)) {
      return false;
    }

#warning we should make the dohpath key configurable, unfortunately.. it seems 7 will be selected but it can still change
    cerr<<"Got "<<resolvers.size()<<" resolver options"<<endl;
    for (const auto& resolver : resolvers) {
      cerr<<"- Priority "<<resolver.first<<" target is "<<resolver.second.target<<endl;
      for (const auto& param : resolver.second.params) {
        cerr<<"\t key: "<<SvcParam::keyToString(param.getKey())<<endl;
        if (param.getKey() == SvcParam::alpn) {
          auto alpns = param.getALPN();
          for (const auto& alpn : alpns) {
            cerr<<"\t alpn: "<<alpn<<endl;
          }
        }
      }
      for (const auto& hint : resolver.second.hints) {
        cerr<<"\t hint: "<<hint.toString()<<endl;
      }
    }

    return true;
  }
  catch (const std::exception& e) {
    errlog("Error while trying to discover backend upgrade for %s: %s", addr.toStringWithPort(), e.what());
  }
  catch (...) {
    errlog("Error while trying to discover backend upgrade for %s", addr.toStringWithPort());
  }

  return false;
}

}

