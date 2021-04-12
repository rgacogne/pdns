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
#include "gettime.hh"
#include "iputils.hh"
#include "uuid-utils.hh"

struct ClientState;
struct DOHUnit;
class DNSCryptQuery;
class DNSDistPacketCache;

using QTag = std::unordered_map<string, string>;

struct StopWatch
{
  StopWatch(bool realTime=false): d_needRealTime(realTime)
  {
  }

  void start() {
    if (gettime(&d_start, d_needRealTime) < 0) {
      unixDie("Getting timestamp");
    }
  }

  void set(const struct timespec& from) {
    d_start = from;
  }

  double udiff() const {
    struct timespec now;
    if (gettime(&now, d_needRealTime) < 0) {
      unixDie("Getting timestamp");
    }

    return 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
  }

  double udiffAndSet() {
    struct timespec now;
    if (gettime(&now, d_needRealTime) < 0) {
      unixDie("Getting timestamp");
    }

    auto ret= 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
    d_start = now;
    return ret;
  }

  struct timespec d_start{0,0};
private:
  bool d_needRealTime{false};
};

struct IDState
{
  IDState(): sentTime(true), delayMsec(0), tempFailureTTL(boost::none) { origDest.sin4.sin_family = 0;}
  IDState(const IDState& orig) = delete;
  IDState(IDState&& rhs): origRemote(rhs.origRemote), origDest(rhs.origDest), sentTime(rhs.sentTime), qname(std::move(rhs.qname)), dnsCryptQuery(std::move(rhs.dnsCryptQuery)), subnet(rhs.subnet), packetCache(std::move(rhs.packetCache)), qTag(std::move(rhs.qTag)), cs(rhs.cs), du(std::move(rhs.du)), cacheKey(rhs.cacheKey), cacheKeyNoECS(rhs.cacheKeyNoECS), age(rhs.age), qtype(rhs.qtype), qclass(rhs.qclass), origID(rhs.origID), origFlags(rhs.origFlags), origFD(rhs.origFD), delayMsec(rhs.delayMsec), tempFailureTTL(rhs.tempFailureTTL), ednsAdded(rhs.ednsAdded), ecsAdded(rhs.ecsAdded), skipCache(rhs.skipCache), destHarvested(rhs.destHarvested), dnssecOK(rhs.dnssecOK), useZeroScope(rhs.useZeroScope)
  {
    if (rhs.isInUse()) {
      throw std::runtime_error("Trying to move an in-use IDState");
    }

    uniqueId = std::move(rhs.uniqueId);
  }

  IDState& operator=(IDState&& rhs)
  {
    if (isInUse()) {
      throw std::runtime_error("Trying to overwrite an in-use IDState");
    }

    if (rhs.isInUse()) {
      throw std::runtime_error("Trying to move an in-use IDState");
    }

    origRemote = rhs.origRemote;
    origDest = rhs.origDest;
    sentTime = rhs.sentTime;
    qname = std::move(rhs.qname);
    dnsCryptQuery = std::move(rhs.dnsCryptQuery);
    subnet = rhs.subnet;
    packetCache = std::move(rhs.packetCache);
    qTag = std::move(rhs.qTag);
    cs = rhs.cs;
    du = std::move(rhs.du);
    cacheKey = rhs.cacheKey;
    cacheKeyNoECS = rhs.cacheKeyNoECS;
    age = rhs.age;
    qtype = rhs.qtype;
    qclass = rhs.qclass;
    origID = rhs.origID;
    origFlags = rhs.origFlags;
    origFD = rhs.origFD;
    delayMsec = rhs.delayMsec;
    tempFailureTTL = rhs.tempFailureTTL;
    ednsAdded = rhs.ednsAdded;
    ecsAdded = rhs.ecsAdded;
    skipCache = rhs.skipCache;
    destHarvested = rhs.destHarvested;
    dnssecOK = rhs.dnssecOK;
    useZeroScope = rhs.useZeroScope;

    uniqueId = std::move(rhs.uniqueId);

    return *this;
  }

  static const int64_t unusedIndicator = -1;

  static bool isInUse(int64_t usageIndicator)
  {
    return usageIndicator != unusedIndicator;
  }

  bool isInUse() const
  {
    return usageIndicator != unusedIndicator;
  }

  /* return true if the value has been successfully replaced meaning that
     no-one updated the usage indicator in the meantime */
  bool tryMarkUnused(int64_t expectedUsageIndicator)
  {
    return usageIndicator.compare_exchange_strong(expectedUsageIndicator, unusedIndicator);
  }

  /* mark as unused no matter what, return true if the state was in use before */
  bool markAsUsed()
  {
    auto currentGeneration = generation++;
    return markAsUsed(currentGeneration);
  }

  /* mark as unused no matter what, return true if the state was in use before */
  bool markAsUsed(int64_t currentGeneration)
  {
    int64_t oldUsage = usageIndicator.exchange(currentGeneration);
    return oldUsage != unusedIndicator;
  }

  /* We use this value to detect whether this state is in use.
     For performance reasons we don't want to use a lock here, but that means
     we need to be very careful when modifying this value. Modifications happen
     from:
     - one of the UDP or DoH 'client' threads receiving a query, selecting a backend
       then picking one of the states associated to this backend (via the idOffset).
       Most of the time this state should not be in use and usageIndicator is -1, but we
       might not yet have received a response for the query previously associated to this
       state, meaning that we will 'reuse' this state and erase the existing state.
       If we ever receive a response for this state, it will be discarded. This is
       mostly fine for UDP except that we still need to be careful in order to miss
       the 'outstanding' counters, which should only be increased when we are picking
       an empty state, and not when reusing ;
       For DoH, though, we have dynamically allocated a DOHUnit object that needs to
       be freed, as well as internal objects internals to libh2o.
     - one of the UDP receiver threads receiving a response from a backend, picking
       the corresponding state and sending the response to the client ;
     - the 'healthcheck' thread scanning the states to actively discover timeouts,
       mostly to keep some counters like the 'outstanding' one sane.
     We previously based that logic on the origFD (FD on which the query was received,
     and therefore from where the response should be sent) but this suffered from an
     ABA problem since it was quite likely that a UDP 'client thread' would reset it to the
     same value since we only have so much incoming sockets:
     - 1/ 'client' thread gets a query and set origFD to its FD, say 5 ;
     - 2/ 'receiver' thread gets a response, read the value of origFD to 5, check that the qname,
       qtype and qclass match
     - 3/ during that time the 'client' thread reuses the state, setting again origFD to 5 ;
     - 4/ the 'receiver' thread uses compare_exchange_strong() to only replace the value if it's still
       5, except it's not the same 5 anymore and it overrides a fresh state.
     We now use a 32-bit unsigned counter instead, which is incremented every time the state is set,
     wrapping around if necessary, and we set an atomic signed 64-bit value, so that we still have -1
     when the state is unused and the value of our counter otherwise.
  */
  std::atomic<int64_t> usageIndicator{unusedIndicator};  // set to unusedIndicator to indicate this state is empty   // 8
  std::atomic<uint32_t> generation{0}; // increased every time a state is used, to be able to detect an ABA issue    // 4
  ComboAddress origRemote;                                    // 28
  ComboAddress origDest;                                      // 28
  ComboAddress hopRemote;
  ComboAddress hopLocal;
  StopWatch sentTime;                                         // 16
  DNSName qname;                                              // 80
  std::shared_ptr<DNSCryptQuery> dnsCryptQuery{nullptr};
  boost::optional<boost::uuids::uuid> uniqueId;
  boost::optional<Netmask> subnet{boost::none};
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  std::shared_ptr<QTag> qTag{nullptr};
  const ClientState* cs{nullptr};
  DOHUnit* du{nullptr};
  uint32_t cacheKey{0};                                       // 4
  uint32_t cacheKeyNoECS{0};                                  // 4
  uint16_t age{0};                                            // 4
  uint16_t qtype{0};                                          // 2
  uint16_t qclass{0};                                         // 2
  uint16_t origID{0};                                         // 2
  uint16_t origFlags{0};                                      // 2
  int origFD{-1};
  int delayMsec{0};
  boost::optional<uint32_t> tempFailureTTL;
  bool ednsAdded{false};
  bool ecsAdded{false};
  bool skipCache{false};
  bool destHarvested{false}; // if true, origDest holds the original dest addr, otherwise the listening addr
  bool dnssecOK{false};
  bool useZeroScope{false};
};