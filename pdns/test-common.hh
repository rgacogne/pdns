
#include "dnsrecords.hh"
#include "iputils.hh"

static inline std::unique_ptr<DNSRecordContent> getRecordContent(uint16_t type, const std::string& content)
{
  std::unique_ptr<DNSRecordContent> result = nullptr;

  if (type == QType::NS) {
    result = make_unique<NSRecordContent>(DNSName(content));
  }
  else if (type == QType::A) {
    result = make_unique<ARecordContent>(ComboAddress(content));
  }
  else if (type == QType::AAAA) {
    result = make_unique<AAAARecordContent>(ComboAddress(content));
  }
  else if (type == QType::CNAME) {
    result = make_unique<CNAMERecordContent>(DNSName(content));
  }
  else if (type == QType::OPT) {
    result = make_unique<OPTRecordContent>();
  }
  else {
    result = DNSRecordContent::mastermake(type, QClass::IN, content);
  }

  return result;
}

static inline void addRecordToList(std::vector<DNSRecord>& records, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=3600)
{
  DNSRecord rec;
  rec.d_place = place;
  rec.d_name = name;
  rec.d_type = type;
  rec.d_ttl = ttl;

  rec.d_content = getRecordContent(type, content);

  records.push_back(rec);
}
