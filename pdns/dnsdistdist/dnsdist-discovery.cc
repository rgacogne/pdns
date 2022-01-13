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

const std::string ServiceDiscovery::s_discoveryDomain{"_dns.resolver.arpa."};
const QType ServiceDiscovery::s_discoveryType{QType::SVCB};
const uint16_t ServiceDiscovery::s_defaultDoHSVCKey{7};

bool ServiceDiscovery::addUpgradeableServer(std::shared_ptr<DownstreamState>& server, uint32_t interval, std::string poolAfterUpgrade, uint16_t dohSVCKey, bool keepAfterUpgrade)
{
  d_upgradeableBackends.emplace_back(UpgradeableBackend{server, poolAfterUpgrade, 0, interval, dohSVCKey, keepAfterUpgrade});
  return true;
}

struct DesignatedResolvers
{
  DNSName target;
  std::set<SvcParam> params;
  std::vector<ComboAddress> hints;
};

static bool parseSVCParams(const PacketBuffer& answer, std::map<uint16_t, DesignatedResolvers>& resolvers)
{
  if (answer.size() <= sizeof(struct dnsheader)) {
    throw std::runtime_error("Looking for SVC records in a packet smaller than a DNS header");
  }

  std::map<DNSName, std::vector<ComboAddress>> hints;
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(answer.data());
  PacketReader pr(pdns_string_view(reinterpret_cast<const char*>(answer.data()), answer.size()));
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

    auto id = getRandomDNSID();
    PacketBuffer packet;
    GenericDNSPacketWriter pw(packet, specialUseDomainName, QType::SVCB);
    pw.getHeader()->id = id;
    pw.getHeader()->rd = 1;
    pw.addOpt(4096, 0, 0);

    uint16_t querySize = static_cast<uint16_t>(packet.size());
    const uint8_t sizeBytes[] = { static_cast<uint8_t>(querySize / 256), static_cast<uint8_t>(querySize % 256) };
    packet.insert(packet.begin(), sizeBytes, sizeBytes + 2);

    Socket sock(addr.sin4.sin_family, SOCK_STREAM);
    sock.setNonBlocking();
    sock.connect(addr, timeout);

    sock.writenWithTimeout(reinterpret_cast<const char*>(packet.data()), packet.size(), timeout);

    uint16_t responseSize = 0;
    auto got = sock.readWithTimeout(reinterpret_cast<char*>(&responseSize), sizeof(responseSize), timeout);
    if (got < 0 || static_cast<size_t>(got) != sizeof(responseSize)) {
      if (g_verbose) {
        warnlog("Error while waiting for the ADD upgrade response from backend %s: %d", addr.toString(), got);
      }
      return false;
    }

    packet.resize(ntohs(responseSize));

    got = sock.readWithTimeout(reinterpret_cast<char *>(packet.data()), packet.size(), timeout);
    if (got < 0 || static_cast<size_t>(got) != packet.size()) {
      if (g_verbose) {
        warnlog("Error while waiting for the ADD upgrade response from backend %s: %d", addr.toString(), got);
      }
      return false;
    }

    if (packet.size() <= sizeof(struct dnsheader)) {
      if (g_verbose) {
        warnlog("Too short answer of size %d received from the backend %s", packet.size(), addr.toString());
      }
      return false;
    }

    struct dnsheader d;
    memcpy(&d, packet.data(), sizeof(d));
    if (d.id != id) {
      if (g_verbose) {
        warnlog("Invalid ID (%d / %d) received from the backend %s", d.id, id, addr.toString());
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
    DNSName receivedName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != specialUseDomainName || receivedType != QType::SVCB || receivedClass != QClass::IN) {
      if (g_verbose) {
        warnlog("Invalid answer, either the qname (%s / %s), qtype (%s / %s) or qclass (%s / %s) does not match, received from the backend %s", receivedName, specialUseDomainName, QType(receivedType).toString(), QType(QType::SVCB).toString(), QClass(receivedClass).toString(), QClass::IN.toString(), addr.toString());
      }
      return false;
    }

    std::map<uint16_t, DesignatedResolvers> resolvers;

    if (!parseSVCParams(packet, resolvers)) {
      return false;
    }

#warning we should make the dohpath key configurable, unfortunately.. it seems 7 will be selected but it can still change
    struct DiscoveredResolverConfig
    {
      ComboAddress d_addr;
      std::string d_dohPath;
      uint16_t d_port{0};
      dnsdist::Protocol d_protocol;
    };

    cerr<<"Got "<<resolvers.size()<<" resolver options"<<endl;
    for (const auto& resolver : resolvers) {
      DiscoveredResolverConfig config;
      config.d_addr.sin4.sin_family = 0;

      cerr<<"- Priority "<<resolver.first<<" target is "<<resolver.second.target<<endl;
      for (const auto& param : resolver.second.params) {
        cerr<<"\t key: "<<SvcParam::keyToString(param.getKey())<<endl;
        if (param.getKey() == SvcParam::alpn) {
          auto alpns = param.getALPN();
          for (const auto& alpn : alpns) {
            cerr<<"\t alpn: "<<alpn<<endl;

            if (alpn == "dot") {
              config.d_protocol = dnsdist::Protocol::DoT;
              if (config.d_port == 0) {
                config.d_port = 853;
              }
            }
            else if (alpn == "h2") {
              config.d_protocol = dnsdist::Protocol::DoH;
              if (config.d_port == 0) {
                config.d_port = 443;
              }
            }
          }
        }
        else if (param.getKey() == SvcParam::port) {
          config.d_port = param.getPort();
        }
        else if (param.getKey() == SvcParam::ipv4hint || param.getKey() == SvcParam::ipv6hint) {
          if (config.d_addr.sin4.sin_family == 0) {
            auto hints = param.getIPHints();
            if (!hints.empty()) {
              config.d_addr = hints.at(0);
            }
          }
        }
        else if (SvcParam::keyToString(param.getKey()) == "key65380") {
          config.d_dohPath = param.getValue();
          auto expression = config.d_dohPath.find('{');
          if (expression != std::string::npos) {
            /* nuke the {?dns} expression, if any, as we only support POST anyway */
            config.d_dohPath.resize(expression);
          }
          cerr<<"\t dohPath: "<<config.d_dohPath<<endl;
        }
      }

      #warning actually we should probably prefer the same address than the one we already know
      if (config.d_addr.sin4.sin_family == 0 && !resolver.second.hints.empty()) {
        config.d_addr = resolver.second.hints.at(0);
      }

      for (const auto& hint : resolver.second.hints) {
        cerr<<"\t hint: "<<hint.toString()<<endl;
      }
      cerr<<config.d_addr.toString()<<endl;
      cerr<<config.d_dohPath<<endl;
      cerr<<config.d_port<<endl;
      cerr<<config.d_protocol.toPrettyString()<<endl;
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

void ServiceDiscovery::worker()
{
  while (!d_upgradeableBackends.empty()) {
    time_t now = time(nullptr);

    for (auto& backend : d_upgradeableBackends) {
      try {
        if (backend.d_nextCheck > now) {
          continue;
        }

        /*
discover=false
discoverDoHKey=7
discoverInterval=3600
discoverPool=""
discoverKeep=false
        */
#warning FIXME: source address and interface
        auto [upgradeable, newConfig] = discoverBackendUpgrade(backend.d_ds, backend.d_dohKey);
        if (upgradeable) {
          /* create new backend, put it into the right pool(s)
             remove the existing backend if needed
             remove backend from list
          */
        }
        else {
          backend.d_nextCheck = now + backend.d_interval;
        }
      }
      catch (const std::exception& e) {
        vinfolog("Exception in the Service Discovery thread: %s", e.what());
      }
      catch (...) {
        vinfolog("Exception in the Service Discovery thread");
      }
    }
  }
}

bool ServiceDiscovery::run()
{
  if (d_upgradeableBackends.empty()) {
    return true;
  }

  d_thread = std::thread(&ServiceDiscovery::worker, this);

  return true;
}

}
