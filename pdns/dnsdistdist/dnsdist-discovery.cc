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

#include "config.h"
#include "dnsdist-discovery.hh"
#include "dnsdist.hh"
#include "dnsparser.hh"
#include "dolog.hh"
#include "sstuff.hh"

namespace dnsdist {

const DNSName ServiceDiscovery::s_discoveryDomain{"_dns.resolver.arpa."};
const QType ServiceDiscovery::s_discoveryType{QType::SVCB};
const uint16_t ServiceDiscovery::s_defaultDoHSVCKey{7};

bool ServiceDiscovery::addUpgradeableServer(std::shared_ptr<DownstreamState>& server, uint32_t interval, std::string poolAfterUpgrade, uint16_t dohSVCKey, bool keepAfterUpgrade)
{
  s_upgradeableBackends.lock()->emplace_back(UpgradeableBackend{server, poolAfterUpgrade, 0, interval, dohSVCKey, keepAfterUpgrade});
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

static bool handleSVCResult(const PacketBuffer& answer, const ComboAddress& existingAddr, uint16_t dohSVCKey, ServiceDiscovery::DiscoveredResolverConfig& config)
{
  std::map<uint16_t, DesignatedResolvers> resolvers;
  if (!parseSVCParams(answer, resolvers)) {
    return false;
  }

  for (const auto& [priority, resolver] : resolvers) {
    /* do not compare the ports */
    std::set<ComboAddress, ComboAddress::addressOnlyLessThan> tentativeAddresses;
    ServiceDiscovery::DiscoveredResolverConfig tempConfig;
    tempConfig.d_addr.sin4.sin_family = 0;

    for (const auto& param : resolver.params) {
      if (param.getKey() == SvcParam::alpn) {
        auto alpns = param.getALPN();
        for (const auto& alpn : alpns) {
          if (alpn == "dot") {
            tempConfig.d_protocol = dnsdist::Protocol::DoT;
            if (tempConfig.d_port == 0) {
              tempConfig.d_port = 853;
            }
          }
          else if (alpn == "h2") {
            tempConfig.d_protocol = dnsdist::Protocol::DoH;
            if (tempConfig.d_port == 0) {
              tempConfig.d_port = 443;
            }
          }
        }
      }
      else if (param.getKey() == SvcParam::port) {
        tempConfig.d_port = param.getPort();
      }
      else if (param.getKey() == SvcParam::ipv4hint || param.getKey() == SvcParam::ipv6hint) {
        if (tempConfig.d_addr.sin4.sin_family == 0) {
          auto hints = param.getIPHints();
          for (const auto& hint : hints) {
            tentativeAddresses.insert(hint);
          }
        }
      }
      else if (dohSVCKey != 0 && param.getKey() == dohSVCKey) {
        tempConfig.d_dohPath = param.getValue();
        auto expression = tempConfig.d_dohPath.find('{');
        if (expression != std::string::npos) {
          /* nuke the {?dns} expression, if any, as we only support POST anyway */
          tempConfig.d_dohPath.resize(expression);
        }
      }
    }

    if (tempConfig.d_protocol == dnsdist::Protocol::DoH){
#ifndef HAVE_DNS_OVER_HTTPS
      continue;
#endif
      if (tempConfig.d_dohPath.empty()) {
        continue;
      }
    }
    else if (tempConfig.d_protocol == dnsdist::Protocol::DoT) {
#ifndef HAVE_DNS_OVER_TLS
      continue;
#endif
    }
    else {
      continue;
    }

    /* we have a config that we can use! */

    for (const auto& hint : resolver.hints) {
      tentativeAddresses.insert(hint);
    }

    /* we prefer the address we already know, whenever possible */
    if (tentativeAddresses.count(existingAddr) != 0) {
      tempConfig.d_addr = existingAddr;
    }
    else {
      tempConfig.d_addr = *tentativeAddresses.begin();
    }

    tempConfig.d_subjectName = resolver.target.toStringNoDot();
    tempConfig.d_addr.sin4.sin_port = tempConfig.d_port;

    config = tempConfig;
    return true;
  }

  return false;
}

bool ServiceDiscovery::getDiscoveredConfig(const UpgradeableBackend& upgradeableBackend, ServiceDiscovery::DiscoveredResolverConfig& config)
{
#warning FIXME: source address and interface
  const auto& backend = upgradeableBackend.d_ds;
  const auto& addr = backend->d_config.remote;
  try {
    auto id = getRandomDNSID();
    PacketBuffer packet;
    GenericDNSPacketWriter pw(packet, s_discoveryDomain, s_discoveryType);
    pw.getHeader()->id = id;
    pw.getHeader()->rd = 1;
    pw.addOpt(4096, 0, 0);

    uint16_t querySize = static_cast<uint16_t>(packet.size());
    const uint8_t sizeBytes[] = { static_cast<uint8_t>(querySize / 256), static_cast<uint8_t>(querySize % 256) };
    packet.insert(packet.begin(), sizeBytes, sizeBytes + 2);

    Socket sock(addr.sin4.sin_family, SOCK_STREAM);
    sock.setNonBlocking();
    sock.connect(addr, backend->d_config.tcpConnectTimeout);

    sock.writenWithTimeout(reinterpret_cast<const char*>(packet.data()), packet.size(), backend->d_config.tcpSendTimeout);

    uint16_t responseSize = 0;
    auto got = sock.readWithTimeout(reinterpret_cast<char*>(&responseSize), sizeof(responseSize), backend->d_config.tcpRecvTimeout);
    if (got < 0 || static_cast<size_t>(got) != sizeof(responseSize)) {
      if (g_verbose) {
        warnlog("Error while waiting for the ADD upgrade response from backend %s: %d", addr.toString(), got);
      }
      return false;
    }

    packet.resize(ntohs(responseSize));

    got = sock.readWithTimeout(reinterpret_cast<char *>(packet.data()), packet.size(), backend->d_config.tcpRecvTimeout);
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
        warnlog("Response code '%s' received from the backend %s for '%s'", RCode::to_s(d.rcode), addr.toString(), s_discoveryDomain);
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

    if (receivedName != s_discoveryDomain || receivedType != s_discoveryType || receivedClass != QClass::IN) {
      if (g_verbose) {
        warnlog("Invalid answer, either the qname (%s / %s), qtype (%s / %s) or qclass (%s / %s) does not match, received from the backend %s", receivedName, s_discoveryDomain, QType(receivedType).toString(), s_discoveryType.toString(), QClass(receivedClass).toString(), QClass::IN.toString(), addr.toString());
      }
      return false;
    }

    return handleSVCResult(packet, addr, upgradeableBackend.d_dohKey, config);
  }
  catch (const std::exception& e) {
    errlog("Error while trying to discover backend upgrade for %s: %s", addr.toStringWithPort(), e.what());
  }
  catch (...) {
    errlog("Error while trying to discover backend upgrade for %s", addr.toStringWithPort());
  }

  return false;
}

bool ServiceDiscovery::tryToUpgradeBackend(const UpgradeableBackend& backend)
{
  ServiceDiscovery::DiscoveredResolverConfig discoveredConfig;

  if (!ServiceDiscovery::getDiscoveredConfig(backend, discoveredConfig)) {
    return false;
  }

  if (discoveredConfig.d_protocol != dnsdist::Protocol::DoT && discoveredConfig.d_protocol != dnsdist::Protocol::DoH) {
    return false;
  }

  DownstreamState::Config config(backend.d_ds->d_config);
  config.remote = discoveredConfig.d_addr;
  if (discoveredConfig.d_port != 0) {
    config.remote.setPort(discoveredConfig.d_port);
  }
  else {
    if (discoveredConfig.d_protocol == dnsdist::Protocol::DoT) {
      config.remote.setPort(853);
    }
    else if (discoveredConfig.d_protocol == dnsdist::Protocol::DoH) {
      config.remote.setPort(443);
    }
  }

  config.d_dohPath = discoveredConfig.d_dohPath;
  config.d_tlsSubjectName = discoveredConfig.d_subjectName;

  if (!backend.d_poolAfterUpgrade.empty()) {
    config.pools.clear();
    config.pools.insert(backend.d_poolAfterUpgrade);
  }

  try {
    /* create new backend, put it into the right pool(s) */
    TLSContextParameters tlsParams;
    auto tlsCtx = getTLSContext(tlsParams);
    auto newServer = std::make_shared<DownstreamState>(std::move(config), std::move(tlsCtx), true);

    infolog("Added automatically upgraded server %s", newServer->getNameWithAddr());

    auto localPools = g_pools.getCopy();
    if (!newServer->d_config.pools.empty()) {
      for (const auto& poolName : newServer->d_config.pools) {
        addServerToPool(localPools, poolName, newServer);
      }
    }
    else {
      addServerToPool(localPools, "", newServer);
    }
    g_pools.setState(localPools);

    newServer->start();

    auto states = g_dstates.getCopy();
    states.push_back(newServer);
    /* remove the existing backend if needed */
    if (!backend.keepAfterUpgrade) {
      for (auto it = states.begin(); it != states.end(); ++it) {
        if (*it == backend.d_ds) {
          states.erase(it);
          break;
        }
      }
    }

    std::stable_sort(states.begin(), states.end(), [](const decltype(newServer)& a, const decltype(newServer)& b) {
      return a->d_config.order < b->d_config.order;
    });
    g_dstates.setState(states);

    return true;
  }
  catch (const std::exception& e) {
    warnlog("Error when trying to upgrade a discovered backend: %s", e.what());
  }

  return false;
}

void ServiceDiscovery::worker()
{
  while (true) {
    time_t now = time(nullptr);

    auto upgradeables = *(s_upgradeableBackends.lock());
    std::set<std::shared_ptr<DownstreamState>> upgradedBackends;

    for (auto backendIt = upgradeables.begin(); backendIt != upgradeables.end(); ) {
      try {
        auto& backend = *backendIt;
        if (backend.d_nextCheck > now) {
          ++backendIt;
          continue;
        }

        /*
discover=false
discoverDoHKey=7
discoverInterval=3600
discoverPool=""
discoverKeep=false
        */
        auto upgraded = tryToUpgradeBackend(backend);
        if (upgraded) {
          upgradedBackends.insert(backend.d_ds);
          backendIt = upgradeables.erase(backendIt);
        }
        else {
          backend.d_nextCheck = now + backend.d_interval;
          ++backendIt;
        }
      }
      catch (const std::exception& e) {
        vinfolog("Exception in the Service Discovery thread: %s", e.what());
      }
      catch (...) {
        vinfolog("Exception in the Service Discovery thread");
      }
    }


    {
      auto backends = s_upgradeableBackends.lock();
      for (auto it = backends->begin(); it != backends->end(); ) {
        if (upgradedBackends.count(it->d_ds) != 0) {
          it = backends->erase(it);
        }
        else {
          ++it;
        }
      }
    }
  }
}

bool ServiceDiscovery::run()
{
  s_thread = std::thread(&ServiceDiscovery::worker);
  s_thread.detach();

  return true;
}

LockGuarded<std::vector<ServiceDiscovery::UpgradeableBackend>> ServiceDiscovery::s_upgradeableBackends;
std::thread ServiceDiscovery::s_thread;
}
