// !! This file has been generated by dnsdist-rules-generator.py, do not edit by hand!!
std::shared_ptr<AllRule> getAllSelector();
std::shared_ptr<DNSSECRule> getDNSSECSelector();
std::shared_ptr<DSTPortRule> getDSTPortSelector(uint16_t port);
std::shared_ptr<EDNSOptionRule> getEDNSOptionSelector(uint16_t option_code);
std::shared_ptr<EDNSVersionRule> getEDNSVersionSelector(uint8_t version);
std::shared_ptr<ERCodeRule> getERCodeSelector(uint64_t rcode);
std::shared_ptr<HTTPHeaderRule> getHTTPHeaderSelector(const std::string& header, const std::string& expression);
std::shared_ptr<HTTPPathRule> getHTTPPathSelector(const std::string& path);
std::shared_ptr<HTTPPathRegexRule> getHTTPPathRegexSelector(const std::string& expression);
std::shared_ptr<LuaFFIPerThreadRule> getLuaFFIPerThreadSelector(const std::string& code);
std::shared_ptr<MaxQPSRule> getMaxQPSSelector(uint32_t qps, std::optional<uint32_t> burst);
std::shared_ptr<MaxQPSIPRule> getMaxQPSIPSelector(uint32_t qps, std::optional<uint8_t> ipv4_mask, std::optional<uint8_t> ipv6_mask, std::optional<uint32_t> burst, std::optional<uint32_t> expiration, std::optional<uint32_t> cleanup_delay, std::optional<uint32_t> scan_fraction, std::optional<uint32_t> shards);
std::shared_ptr<OpcodeRule> getOpcodeSelector(uint8_t code);
std::shared_ptr<PayloadSizeRule> getPayloadSizeSelector(const std::string& comparison, uint16_t size);
std::shared_ptr<PoolAvailableRule> getPoolAvailableSelector(const std::string& pool);
std::shared_ptr<PoolOutstandingRule> getPoolOutstandingSelector(const std::string& pool, uint64_t max_outstanding);
std::shared_ptr<ProbaRule> getProbaSelector(double probability);
std::shared_ptr<ProxyProtocolValueRule> getProxyProtocolValueSelector(uint8_t option_type, std::optional<std::string> option_value);
std::shared_ptr<QNameLabelsCountRule> getQNameLabelsCountSelector(uint16_t min_labels_count, uint16_t max_labels_count);
std::shared_ptr<QNameWireLengthRule> getQNameWireLengthSelector(uint16_t min, uint16_t max);
std::shared_ptr<RCodeRule> getRCodeSelector(uint64_t rcode);
std::shared_ptr<RDRule> getRDSelector();
std::shared_ptr<RE2Rule> getRE2Selector(const std::string& expression);
std::shared_ptr<RecordsCountRule> getRecordsCountSelector(uint8_t section, uint16_t minimum, uint16_t maximum);
std::shared_ptr<RecordsTypeCountRule> getRecordsTypeCountSelector(uint8_t section, uint16_t record_type, uint16_t minimum, uint16_t maximum);
std::shared_ptr<RegexRule> getRegexSelector(const std::string& expression);
std::shared_ptr<SNIRule> getSNISelector(const std::string& server_name);
std::shared_ptr<TagRule> getTagSelector(const std::string& tag, std::optional<std::string> value, std::optional<bool> emptyAsWildcard);
std::shared_ptr<TCPRule> getTCPSelector(bool tcp);
std::shared_ptr<TrailingDataRule> getTrailingDataSelector();
