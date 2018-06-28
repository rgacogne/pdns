#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/test/floating_point_comparison.hpp>

#include "iputils.hh"
#include "recursor_cache.hh"
#include "syncres.hh"

__thread SyncRes::StaticStorage* t_sstorage = nullptr;
unsigned int g_numThreads = 1;

BOOST_AUTO_TEST_SUITE(recursorcache_cc)

BOOST_AUTO_TEST_CASE(test_RecursorCacheGhost) {
  MemRecursorCache MRC;

  set<DNSResourceRecord> records;
  time_t now = time(nullptr);

  BOOST_CHECK_EQUAL(MRC.size(), 0);

  /* insert NS coming from a delegation */
  time_t ttd = now + 30;
  std::string ghost("ghost.powerdns.com.");
  DNSResourceRecord ns1;
  std::string ns1Content("ns1.ghost.powerdns.com.");
  ns1.qname = ghost;
  ns1.qtype = QType::NS;
  ns1.qclass = QClass::IN;
  ns1.setContent(ns1Content);
  ns1.ttl = static_cast<uint32_t>(ttd);
  ns1.d_place = DNSResourceRecord::ANSWER;
  records.insert(ns1);
  MRC.replace(now, ns1.qname, QType(ns1.qtype), records, true);
  BOOST_CHECK_EQUAL(MRC.size(), 1);

  /* try to raise the TTL, simulating the delegated authoritative server
     raising the TTL so the zone stays alive */
  records.clear();
  ns1.ttl = static_cast<uint32_t>(ttd + 3600);
  records.insert(ns1);
  MRC.replace(now, ns1.qname, QType(ns1.qtype), records, true);
  BOOST_CHECK_EQUAL(MRC.size(), 1);

  /* the TTL should not have been raisd */
  set<DNSResourceRecord> retrieved;
  BOOST_CHECK_EQUAL(MRC.get(now, ghost, QType(QType::NS), &retrieved), (ttd-now));
  BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
  BOOST_CHECK_EQUAL(retrieved.begin()->ttl, static_cast<uint32_t>(ttd));
}

BOOST_AUTO_TEST_SUITE_END()
