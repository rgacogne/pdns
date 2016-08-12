#pragma once
#include "filterpo.hh"
#include <string>
#include "dnsrecords.hh"

int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, boost::optional<DNSFilterEngine::Policy> defpol, size_t place);
std::shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zone, DNSFilterEngine& target, boost::optional<DNSFilterEngine::Policy> defpol, size_t place, const TSIGTriplet& tt, size_t maxReceivedBytes);
void RPZRecordToPolicy(const DNSRecord& dr, DNSFilterEngine& target, bool addOrRemove, boost::optional<DNSFilterEngine::Policy> defpol, size_t place);
void RPZIXFRTracker(const ComboAddress& master, const DNSName& zone, size_t polZone, const TSIGTriplet &tt, shared_ptr<SOARecordContent> oursr, size_t maxReceivedBytes);
