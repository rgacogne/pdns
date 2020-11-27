
#include "aggressivensec.hh"
#include "cachecleaner.hh"
#include "validate.hh"

void AggressiveNSECZoneData::addSOA(const DNSRecord& soa, const std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures)
{
  std::lock_guard<std::mutex> lock(d_lock);
#warning todo: SOA TTD
  d_soa = soa;
  d_soaSignatures = signatures;
}

void AggressiveNSECZoneData::addNSEC(const DNSName& name, time_t ttd, const DNSRecord& record, const std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures)
{
  cerr<<"added entry for "<<name<<endl;
  CacheEntry ce;
  ce.d_signatures = signatures;
  ce.d_name = name;
  ce.d_record = record;

#warning TODO: ttd
  std::lock_guard<std::mutex> lock(d_lock);
  d_records.insert(ce);
}

bool AggressiveNSECZoneData::getNSEC(const DNSName& name, uint16_t qtype, time_t now, DNSRecord& nsec, std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures, bool& exact)
{
#warning TODO: check ttd
  cerr<<"looking for "<<name<<endl;
  std::lock_guard<std::mutex> lock(d_lock);
  auto& idx = d_records.get<OrderedTag>();
  if (idx.empty()) {
    cerr<<"empty"<<endl;
    return false;
  }
  auto entry = idx.upper_bound(name);
  bool end = false;
  while (!end && (entry == idx.end() || !entry->d_name.canonCompare(name))) {
    if (entry == idx.begin()) {
      // can't go further
      // TODO might be good to check for a wrapping cases!
      cerr<<"can't go further, sorry"<<endl;
      end = true;
    }
    else {
      entry--;
      cerr<<"looping with "<<entry->d_name<<endl;
    }
  }

  if (end) {
    cerr<<"nothing!"<<endl;
    return false;
  }

  cerr<<"got "<<entry->d_name<<endl;

  bool covered = false;
  auto denial = matchesNSEC(name, qtype, entry->d_record, entry->d_signatures);
  if (denial == dState::NXQTYPE) {
    exact = true;
    covered = true;
    cerr<<"boom!"<<endl;
  }
  else if (denial == dState::NXDOMAIN) {
    cerr<<"covered!"<<endl;
    covered = true;
  }

  if (covered) {
    nsec = entry->d_record;
    signatures = entry->d_signatures;
    moveCacheItemToBack<SequencedTag>(d_records, entry);
  }

  return covered;
}
