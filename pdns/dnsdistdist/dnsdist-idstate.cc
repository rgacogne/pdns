
#include "dnsdist.hh"

static void setDNSQuestionFromIDState(DNSQuestion& dq, IDState& ids)
{
  dq.origFlags = ids.origFlags;
  dq.cacheFlags = ids.cacheFlags;
  dq.ecsAdded = ids.ecsAdded;
  dq.ednsAdded = ids.ednsAdded;
  dq.useZeroScope = ids.useZeroScope;
  dq.packetCache = ids.packetCache;
  dq.delayMsec = ids.delayMsec;
  dq.skipCache = ids.skipCache;
  dq.cacheKey = ids.cacheKey;
  dq.cacheKeyNoECS = ids.cacheKeyNoECS;
  dq.cacheKeyUDP = ids.cacheKeyUDP;
  dq.dnssecOK = ids.dnssecOK;
  dq.tempFailureTTL = ids.tempFailureTTL;
  dq.qTag = std::move(ids.qTag);
  dq.subnet = std::move(ids.subnet);
  dq.uniqueId = std::move(ids.uniqueId);

  if (ids.dnsCryptQuery) {
    dq.dnsCryptQuery = std::move(ids.dnsCryptQuery);
  }

  dq.hopRemote = &ids.hopRemote;
  dq.hopLocal = &ids.hopLocal;
  dq.d_cs = ids.cs;

  dq.du = ids.du;

}

DNSQuestion makeDNSQuestionFromIDState(IDState& ids, PacketBuffer& data)
{
  DNSQuestion dq(&ids.qname, ids.qtype, ids.qclass, &ids.origDest, &ids.origRemote, data, ids.protocol, &ids.sentTime.d_start);

  setDNSQuestionFromIDState(dq, ids);

  return dq;
}

DNSResponse makeDNSResponseFromIDState(IDState& ids, PacketBuffer& data, const std::shared_ptr<DownstreamState>& ds)
{
  DNSResponse dr(&ids.qname, ids.qtype, ids.qclass, &ids.origDest, &ids.origRemote, data, ids.protocol, &ids.sentTime.d_start, ds);

  setDNSQuestionFromIDState(dr, ids);

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
