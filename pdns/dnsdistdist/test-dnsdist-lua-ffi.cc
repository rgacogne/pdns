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
    // dnsdist_ffi_dnsquestion_get_qname_raw
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_qname_raw(&lightDQ, &buffer, &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, ids.qname.getStorage().size());
    BOOST_CHECK(memcmp(buffer, ids.qname.getStorage().data(), ids.qname.getStorage().size()) == 0);
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
    dnsdist_ffi_dnsquestion_set_size(&lightDQ, oldSize);
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
  }
}

BOOST_AUTO_TEST_SUITE_END();
