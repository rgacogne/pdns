
#include "dnsdist.hh"

DNSResponse makeDNSResponseFromIDState(IDState& ids, PacketBuffer& data, const std::shared_ptr<DownstreamState>& ds)
{
  DNSResponse dr(&ids.qname, ids.qtype, ids.qclass, &ids.origDest, &ids.origRemote, data, ids.protocol, &ids.sentTime.d_start, ds);

  dr.origFlags = ids.origFlags;
  dr.cacheFlags = ids.cacheFlags;
  dr.ecsAdded = ids.ecsAdded;
  dr.ednsAdded = ids.ednsAdded;
  dr.useZeroScope = ids.useZeroScope;
  dr.packetCache = std::move(ids.packetCache);
  dr.delayMsec = ids.delayMsec;
  dr.skipCache = ids.skipCache;
  dr.cacheKey = ids.cacheKey;
  dr.cacheKeyNoECS = ids.cacheKeyNoECS;
  dr.cacheKeyUDP = ids.cacheKeyUDP;
  dr.dnssecOK = ids.dnssecOK;
  dr.tempFailureTTL = ids.tempFailureTTL;
  dr.qTag = std::move(ids.qTag);
  dr.subnet = std::move(ids.subnet);
  dr.uniqueId = std::move(ids.uniqueId);

  if (ids.dnsCryptQuery) {
    dr.dnsCryptQuery = std::move(ids.dnsCryptQuery);
  }

  dr.hopRemote = &ids.hopRemote;
  dr.hopLocal = &ids.hopLocal;
  dr.d_cs = ids.cs;

  dr.du = ids.du;
  return dr;
}

void setIDStateFromDNSQuestion(IDState& ids, DNSQuestion& dq, DNSName&& qname, uint16_t queryID)
{
  ids.origRemote = *dq.remote;
  ids.origDest = *dq.local;
  ids.cs = dq.getFrontend();
  if (ids.origDest.sin4.sin_family == 0 && ids.cs != nullptr) {
    /* If we couldn't harvest the real dest addr, still
       write down the listening addr since it will be useful
       (especially if it's not an 'any' one).
    */
    ids.origDest = ids.cs->local;
  }
  ids.sentTime.set(*dq.queryTime);
  ids.qname = std::move(qname);
  ids.qtype = dq.qtype;
  ids.qclass = dq.qclass;
  ids.protocol = dq.protocol;
  ids.delayMsec = dq.delayMsec;
  ids.tempFailureTTL = dq.tempFailureTTL;
  ids.origFlags = dq.origFlags;
  ids.cacheFlags = dq.cacheFlags;
  ids.cacheKey = dq.cacheKey;
  ids.cacheKeyNoECS = dq.cacheKeyNoECS;
  ids.cacheKeyUDP = dq.cacheKeyUDP;
  ids.subnet = dq.subnet;
  ids.skipCache = dq.skipCache;
  ids.packetCache = dq.packetCache;
  ids.ednsAdded = dq.ednsAdded;
  ids.ecsAdded = dq.ecsAdded;
  ids.useZeroScope = dq.useZeroScope;
  ids.qTag = std::move(dq.qTag);
  ids.dnssecOK = dq.dnssecOK;
  ids.uniqueId = std::move(dq.uniqueId);

  if (dq.hopRemote) {
    ids.hopRemote = *dq.hopRemote;
  }
  else {
    ids.hopRemote.sin4.sin_family = 0;
  }

  if (dq.hopLocal) {
    ids.hopLocal = *dq.hopLocal;
  }
  else {
    ids.hopLocal.sin4.sin_family = 0;
  }

  ids.origID = queryID;
  ids.dnsCryptQuery = std::move(dq.dnsCryptQuery);
  ids.du = dq.du;
}
