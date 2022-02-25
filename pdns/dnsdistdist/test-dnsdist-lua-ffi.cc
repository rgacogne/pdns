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
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-lua-ffi.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_lua_ffi)

BOOST_AUTO_TEST_CASE(test_Query)
{
  struct timespec queryTime;
  gettime(&queryTime);

  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(42);

  DNSQuestion dq(ids, query, queryTime);
  dnsdist_ffi_dnsquestion_t lightDQ(&dq);

  {
    // dnsdist_ffi_dnsquestion_get_qtype
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_qtype(&lightDQ), ids.qtype);
  }

  {
    // dnsdist_ffi_dnsquestion_get_qclass
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_qclass(&lightDQ), ids.qclass);
  }

  {
    // dnsdist_ffi_dnsquestion_get_id
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_id(&lightDQ), ntohs(pwQ.getHeader()->id));
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_id(nullptr), 0U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_localaddr, dnsdist_ffi_dnsquestion_get_local_port
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_localaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(ids.origDest.sin4.sin_addr.s_addr));
    BOOST_CHECK(memcmp(buffer, &ids.origDest.sin4.sin_addr.s_addr, sizeof(ids.origDest.sin4.sin_addr.s_addr)) == 0);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_local_port(&lightDQ), 53U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_remoteaddr, dnsdist_ffi_dnsquestion_get_remote_port
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_remoteaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(ids.origDest.sin4.sin_addr.s_addr));
    BOOST_CHECK(memcmp(buffer, &ids.origRemote.sin4.sin_addr.s_addr, sizeof(ids.origRemote.sin4.sin_addr.s_addr)) == 0);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_remote_port(&lightDQ), 4242U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_masked_remoteaddr
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_masked_remoteaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize, 16);
    BOOST_REQUIRE(buffer != nullptr);
    auto masked = Netmask(ids.origRemote, 16).getMaskedNetwork();
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(masked.sin4.sin_addr.s_addr));
    BOOST_CHECK(memcmp(buffer, &masked.sin4.sin_addr.s_addr, sizeof(masked.sin4.sin_addr.s_addr)) == 0);
  }

  {
    const char* buffer[6];
    size_t bufferSize = 6;

    // invalid
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_mac_addr(nullptr, buffer, 0), 0U);
    // too small
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_mac_addr(&lightDQ, buffer, 0), 0U);

    // we will not find the correspondig MAC address in /proc/net/arp, unfortunately, especially not on !linux
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_mac_addr(&lightDQ, buffer, bufferSize), 0U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_qname_raw
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_qname_raw(&lightDQ, &buffer, &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, ids.qname.getStorage().size());
    BOOST_CHECK(memcmp(buffer, ids.qname.getStorage().data(), ids.qname.getStorage().size()) == 0);
  }

  {
    // test V6 as well
    ids.origRemote = ComboAddress("[2001:db8::1]:65535");
    ids.origDest = ComboAddress("[2001:db8::2]:53");

    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_remoteaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(ids.origDest.sin6.sin6_addr.s6_addr));
    BOOST_CHECK(memcmp(buffer, &ids.origRemote.sin6.sin6_addr.s6_addr, sizeof(ids.origRemote.sin6.sin6_addr.s6_addr)) == 0);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_remote_port(&lightDQ), 65535U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_qname_hash
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_qname_hash(&lightDQ, 42), ids.qname.hash(42));
  }

  {
    // dnsdist_ffi_dnsquestion_get_rcode
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_rcode(&lightDQ), RCode::NoError);
  }

  {
    // dnsdist_ffi_dnsquestion_get_header
    BOOST_CHECK(memcmp(dnsdist_ffi_dnsquestion_get_header(&lightDQ), pwQ.getHeader(), sizeof(dnsheader)) == 0);
  }

  {
    // dnsdist_ffi_dnsquestion_get_len, dnsdist_ffi_dnsquestion_get_size
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_len(&lightDQ), query.size());
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_size(&lightDQ), query.size());

    auto oldSize = query.size();
    BOOST_CHECK(dnsdist_ffi_dnsquestion_set_size(&lightDQ, oldSize + 1));
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_size(&lightDQ), oldSize + 1);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_len(&lightDQ), oldSize + 1);
    dnsdist_ffi_dnsquestion_set_len(&lightDQ, oldSize);

    auto max = std::numeric_limits<size_t>::max();
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_set_size(&lightDQ, max), 0U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_opcode
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_opcode(&lightDQ), Opcode::Query);
  }

  {
    // dnsdist_ffi_dnsquestion_get_tcp
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tcp(&lightDQ), false);
  }

  {
    // dnsdist_ffi_dnsquestion_get_protocol
    BOOST_CHECK(static_cast<uint8_t>(dnsdist_ffi_dnsquestion_get_protocol(&lightDQ)) == dnsdist::Protocol(dnsdist::Protocol::DoUDP).toNumber());
    for (const auto protocol : {dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoTCP, dnsdist::Protocol::DNSCryptUDP, dnsdist::Protocol::DNSCryptTCP, dnsdist::Protocol::DoT, dnsdist::Protocol::DoH}) {
      dq.ids.protocol = protocol;
      BOOST_CHECK(static_cast<uint8_t>(dnsdist_ffi_dnsquestion_get_protocol(&lightDQ)) == protocol);
    }
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_skip_cache(&lightDQ), false);
    dnsdist_ffi_dnsquestion_set_skip_cache(&lightDQ, true);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_skip_cache(&lightDQ), true);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_use_ecs(&lightDQ), true);
    dnsdist_ffi_dnsquestion_set_use_ecs(&lightDQ, false);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_use_ecs(&lightDQ), false);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_add_xpf(&lightDQ), true);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_override(&lightDQ), false);
    dnsdist_ffi_dnsquestion_set_ecs_override(&lightDQ, true);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_override(&lightDQ), true);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(&lightDQ), false);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_temp_failure_ttl(&lightDQ), 0U);

    dnsdist_ffi_dnsquestion_set_temp_failure_ttl(&lightDQ, 42);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(&lightDQ), true);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_temp_failure_ttl(&lightDQ), 42U);
    dnsdist_ffi_dnsquestion_unset_temp_failure_ttl(&lightDQ);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(&lightDQ), false);
  }

  {
    BOOST_CHECK(!dnsdist_ffi_dnsquestion_get_do(&lightDQ));
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_prefix_length(&lightDQ), g_ECSSourcePrefixV4);
    dnsdist_ffi_dnsquestion_set_ecs_prefix_length(&lightDQ, 65535);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_prefix_length(&lightDQ), 65535U);
  }

  {
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_sni(&lightDQ, &buffer, &bufferSize);
    BOOST_CHECK_EQUAL(bufferSize, 0U);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_trailing_data(&lightDQ, nullptr), 0U);
#if 0
    // DNSQuestion::setTrailingData() and DNSQuestion::getTrailingData() are currently stubs in the test runner
    std::string garbage("thisissomegarbagetrailingdata");
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_set_trailing_data(&lightDQ, garbage.data(), garbage.size()), true);
    const char* buffer = nullptr;
    BOOST_REQUIRE_EQUAL(dnsdist_ffi_dnsquestion_get_trailing_data(&lightDQ, &buffer), garbage.size());
    BOOST_CHECK_EQUAL(garbage, std::string(buffer));
#endif
  }

  {
#if 0
    // SpoofAction::operator() is a stub in the test runner
    auto oldData = dq.getData();
    std::vector<dnsdist_ffi_raw_value> values;
    ComboAddress v4("192.0.2.1");
    ComboAddress v6("[2001:db8::42]");
    values.push_back({ reinterpret_cast<const char*>(&v4.sin4.sin_addr.s_addr), sizeof(v4.sin4.sin_addr.s_addr)});
    values.push_back({ reinterpret_cast<const char*>(&v6.sin6.sin6_addr.s6_addr), sizeof(v6.sin6.sin6_addr.s6_addr)});

    dnsdist_ffi_dnsquestion_spoof_addrs(&lightDQ, values.data(), values.size());
    BOOST_CHECK(dq.getData().size() > oldData.size());

    MOADNSParser mdp(false, reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size());
    BOOST_CHECK_EQUAL(mdp.d_qname, ids.qname);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, values.size());
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_type, static_cast<uint16_t>(QType::A));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_name, ids.qname);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).first.d_type, static_cast<uint16_t>(QType::AAAA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).first.d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).first.d_name, ids.qname);

    dq.getMutableData() = oldData;
#endif
  }

  {
    BOOST_CHECK(!dnsdist_ffi_dnsquestion_set_restartable(nullptr));
    BOOST_CHECK(dnsdist_ffi_dnsquestion_set_restartable(&lightDQ));
  }

  {
    BOOST_CHECK_EQUAL(ids.ttlCap, 0U);
    dnsdist_ffi_dnsquestion_set_max_returned_ttl(&lightDQ, 42U);
    BOOST_CHECK_EQUAL(ids.ttlCap, 42U);

    BOOST_CHECK(ids.ttlCapTypes.empty());
    dnsdist_ffi_dnsquestion_add_type_to_max_returned_ttl(&lightDQ, QType::A);
    dnsdist_ffi_dnsquestion_add_type_to_max_returned_ttl(&lightDQ, QType::AAAA);
    BOOST_CHECK_EQUAL(ids.ttlCapTypes.size(), 2U);
    BOOST_CHECK_EQUAL(ids.ttlCapTypes.count(QType::A), 1U);
    BOOST_CHECK_EQUAL(ids.ttlCapTypes.count(QType::AAAA), 1U);
  }

  {
    const std::string tagName("my-tag");
    const std::string tagValue("my-value");
    const std::string tagRawValue("my-\0-binary-value");
    std::string buffer;
    buffer.resize(512);
    BOOST_CHECK(dnsdist_ffi_dnsquestion_get_tag(nullptr, nullptr) == nullptr);
    BOOST_CHECK(dnsdist_ffi_dnsquestion_get_tag(&lightDQ, nullptr) == nullptr);
    BOOST_CHECK(dnsdist_ffi_dnsquestion_get_tag(&lightDQ, tagName.c_str()) == nullptr);

    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(nullptr, nullptr, nullptr, 0), 0U);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(&lightDQ, tagName.c_str(), buffer.data(), buffer.size()), 0U);

    dnsdist_ffi_dnsquestion_set_tag(&lightDQ, tagName.c_str(), tagValue.c_str());

    auto got = dnsdist_ffi_dnsquestion_get_tag(&lightDQ, tagName.c_str());
    BOOST_CHECK(got != nullptr);
    BOOST_CHECK_EQUAL(got, tagValue.c_str());

    const dnsdist_ffi_tag_t* tags = nullptr;
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_array(nullptr, nullptr), 0U);
    BOOST_REQUIRE_EQUAL(dnsdist_ffi_dnsquestion_get_tag_array(&lightDQ, &tags), 1U);
    BOOST_CHECK_EQUAL(std::string(tags[0].name), tagName.c_str());
    BOOST_CHECK_EQUAL(std::string(tags[0].value), tagValue.c_str());

    dnsdist_ffi_dnsquestion_set_tag_raw(&lightDQ, tagName.c_str(), tagRawValue.c_str(), tagRawValue.size());

    // too small
    buffer.resize(1);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(&lightDQ, tagName.c_str(), buffer.data(), buffer.size()), 0U);

    buffer.resize(tagRawValue.size());
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(&lightDQ, tagName.c_str(), buffer.data(), buffer.size()), tagRawValue.size());
    BOOST_CHECK_EQUAL(buffer, tagRawValue);

    // dnsdist_ffi_dnsquestion_set_tag
    // dnsdist_ffi_dnsquestion_get_tag
    // dnsdist_ffi_dnsquestion_get_tag_raw
    // dnsdist_ffi_dnsquestion_get_tag_array
  }
}

BOOST_AUTO_TEST_CASE(test_Response)
{
  struct timespec queryTime;
  gettime(&queryTime);

  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");
  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::A, QClass::IN, 0);
  pwR.getHeader()->qr = 1;
  pwR.getHeader()->rd = 1;
  pwR.getHeader()->id = htons(42);

  ComboAddress dsAddr("192.0.2.1:53");
  auto ds = std::make_shared<DownstreamState>(dsAddr);

  DNSResponse dr(ids, response, queryTime, ds);
  dnsdist_ffi_dnsresponse_t lightDR(&dr);

  {
    dnsdist_ffi_dnsresponse_set_min_ttl(&lightDR, 42);
    dnsdist_ffi_dnsresponse_set_max_ttl(&lightDR, 84);
    dnsdist_ffi_dnsresponse_limit_ttl(&lightDR, 42, 84);
  }

  {
    BOOST_CHECK_EQUAL(ids.ttlCap, 0U);
    dnsdist_ffi_dnsresponse_set_max_returned_ttl(&lightDR, 42);
    BOOST_CHECK_EQUAL(ids.ttlCap, 42U);

    BOOST_CHECK(ids.ttlCapTypes.empty());
    dnsdist_ffi_dnsresponse_add_type_to_max_returned_ttl(&lightDR, QType::A);
    dnsdist_ffi_dnsresponse_add_type_to_max_returned_ttl(&lightDR, QType::AAAA);
    BOOST_CHECK_EQUAL(ids.ttlCapTypes.size(), 2U);
    BOOST_CHECK_EQUAL(ids.ttlCapTypes.count(QType::A), 1U);
    BOOST_CHECK_EQUAL(ids.ttlCapTypes.count(QType::AAAA), 1U);
  }

  {
    /* invalid parameters */
    BOOST_CHECK(!dnsdist_ffi_dnsresponse_rebase(&lightDR, nullptr, 0));

    /* invalid name */
    BOOST_CHECK(!dnsdist_ffi_dnsresponse_rebase(&lightDR, "\5AAAA", 5));

    DNSName newName("not-powerdns.com.");
    BOOST_CHECK(dnsdist_ffi_dnsresponse_rebase(&lightDR, newName.getStorage().data(), newName.getStorage().size()));
    BOOST_CHECK_EQUAL(ids.qname.toString(), newName.toString());
  }

  {
    dnsdist_ffi_dnsresponse_clear_records_type(nullptr, QType::A);
    dnsdist_ffi_dnsresponse_clear_records_type(&lightDR, QType::A);
  }
}

BOOST_AUTO_TEST_CASE(test_Server)
{
  ComboAddress dsAddr("192.0.2.1:53");
  auto ds = std::make_shared<DownstreamState>(dsAddr);
  dnsdist_ffi_server_t server(ds);

  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_outstanding(&server), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_is_up(&server), false);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_name(&server), "");
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_name_with_addr(&server), dsAddr.toStringWithPort());
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_weight(&server), 1U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_order(&server), 1U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_latency(&server), 0.0);
}

BOOST_AUTO_TEST_CASE(test_PacketOverlay)
{
  const DNSName target("powerdns.com.");
  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::A, QClass::IN, 0);
  pwR.getHeader()->qr = 1;
  pwR.getHeader()->rd = 1;
  pwR.getHeader()->ra = 1;
  pwR.getHeader()->id = htons(42);
  pwR.startRecord(target, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
  ComboAddress v4("192.0.2.1");
  pwR.xfrCAWithoutPort(4, v4);
  pwR.commit();
  pwR.startRecord(target, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
  ComboAddress v6("2001:db8::1");
  pwR.xfrCAWithoutPort(6, v6);
  pwR.commit();
  pwR.addOpt(4096, 0, 0);
  pwR.commit();

  /* invalid parameters */
  BOOST_CHECK(!dnsdist_ffi_dnspacket_parse(nullptr, 0, nullptr));

  dnsdist_ffi_dnspacket_t* packet = nullptr;
  // invalid packet
  BOOST_CHECK(!dnsdist_ffi_dnspacket_parse(reinterpret_cast<const char*>(response.data()), response.size() - 1, &packet));
  BOOST_REQUIRE(dnsdist_ffi_dnspacket_parse(reinterpret_cast<const char*>(response.data()), response.size(), &packet));
  BOOST_REQUIRE(packet != nullptr);

  const char* qname = nullptr;
  size_t qnameSize = 0;

  // invalid parameters
  dnsdist_ffi_dnspacket_get_qname_raw(nullptr, nullptr, 0);

  dnsdist_ffi_dnspacket_get_qname_raw(packet, &qname, &qnameSize);
  BOOST_REQUIRE(qname != nullptr);
  BOOST_REQUIRE_EQUAL(qnameSize, target.wirelength());
  BOOST_CHECK_EQUAL(memcmp(qname, target.getStorage().data(), target.getStorage().size()), 0);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qtype(nullptr), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qclass(nullptr), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qtype(packet), QType::A);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qclass(packet), QClass::IN);

  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 1), 1U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 2), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 3), 2U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 4), 0U);

  const char* name = nullptr;
  size_t nameSize = 0;
  dnsdist_ffi_dnspacket_get_record_name_raw(nullptr, 0, nullptr, 0);
  BOOST_REQUIRE(name == nullptr);

  // invalid parameters
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_type(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_class(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_ttl(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_length(nullptr, 0), 0U);

  // first record */
  dnsdist_ffi_dnspacket_get_record_name_raw(packet, 0, &name, &nameSize);
  BOOST_REQUIRE(name != nullptr);
  BOOST_REQUIRE_EQUAL(nameSize, target.wirelength());
  BOOST_CHECK_EQUAL(memcmp(name, target.getStorage().data(), target.getStorage().size()), 0);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_type(packet, 0), QType::A);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_class(packet, 0), QClass::IN);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_ttl(packet, 0), 7200U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_length(packet, 0), sizeof(v4.sin4.sin_addr.s_addr));
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_offset(packet, 0), 42U);

  // second record
  dnsdist_ffi_dnspacket_get_record_name_raw(packet, 1, &name, &nameSize);
  BOOST_REQUIRE(name != nullptr);
  BOOST_REQUIRE_EQUAL(nameSize, target.wirelength());
  BOOST_CHECK_EQUAL(memcmp(name, target.getStorage().data(), target.getStorage().size()), 0);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_type(packet, 1), QType::AAAA);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_class(packet, 1), QClass::IN);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_ttl(packet, 1), 7200U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_length(packet, 1), sizeof(v6.sin6.sin6_addr.s6_addr));
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_offset(packet, 1), 58U);

  dnsdist_ffi_dnspacket_free(packet);
}

BOOST_AUTO_TEST_SUITE_END();
