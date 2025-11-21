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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <atomic>
#include <iostream>
#include <fstream>
#include <memory>
#include <poll.h>
#include <thread>

#include <boost/program_options.hpp>

#include "dns_random.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "misc.hh"
#include "proxy-protocol.hh"
#include "sstuff.hh"
#include "statbag.hh"

StatBag S;

namespace po = boost::program_options;

struct WorkerMetrics
{
  std::atomic<uint64_t> recvCounter{0};
  std::atomic<uint64_t> recvBytes{0};
};

//NOLINTNEXTLINE(performance-unnecessary-value-param): we do want a copy to increase the reference count, thank you very much
static void recvThread(const std::shared_ptr<std::vector<std::unique_ptr<Socket>>> sockets, WorkerMetrics& metrics)
{
  std::vector<pollfd> rfds, fds;
  for (const auto& sock : *sockets) {
    if (sock == nullptr) {
      continue;
    }
    pollfd pfd{};
    pfd.fd = sock->getHandle();
    pfd.events = POLLIN;
    pfd.revents = 0;
    rfds.push_back(pfd);
  }

#ifdef HAVE_RECVMMSG
  std::vector<struct mmsghdr> buffers(100);
  for (auto& buffer : buffers) {
    cmsgbuf_aligned *cbuf = new cmsgbuf_aligned;
    fillMSGHdr(&buffer.msg_hdr, new struct iovec, cbuf, sizeof(*cbuf), new char[1500], 1500, new ComboAddress("127.0.0.1"));
  }
#else
  struct msghdr buf;
  cmsgbuf_aligned *cbuf = new cmsgbuf_aligned;
  fillMSGHdr(&buf, new struct iovec, cbuf, sizeof(*cbuf), new char[1500], 1500, new ComboAddress("127.0.0.1"));
#endif

  while (true) {
    fds = rfds;

    auto err = poll(&fds[0], fds.size(), -1);
    if (err < 0) {
      if (errno == EINTR) {
        continue;
      }
      unixDie("Unable to poll for new UDP events");
    }

    for (auto &pfd : fds) {
      if ((pfd.revents & POLLIN) == 0) {
        continue;
      }

#ifdef HAVE_RECVMMSG
      if ((err = recvmmsg(pfd.fd, buffers.data(), buffers.size(), MSG_WAITFORONE, 0)) < 0 ) {
        if (errno != EAGAIN) {
          unixDie("recvmmsg");
        }
        continue;
      }

      metrics.recvCounter += err;
      for (int idx = 0; idx < err; ++idx) {
        metrics.recvBytes += buffers.at(idx).msg_len;
      }
#else
      if ((err = recvmsg(pfd.fd, &buf, 0)) < 0) {
        if (errno != EAGAIN) {
          unixDie("recvmsg");
        }
        continue;
      }
      ++metrics.recvCounter;
      for (decltype(buf.msg_iovlen) idx = 0; idx < buf.msg_iovlen; idx++)
        metrics.recvBytes += buf.msg_iov[idx].iov_len;
#endif
    }
  }
}

static ComboAddress getRandomAddressFromRange(const Netmask& range)
{
  ComboAddress result = range.getMaskedNetwork();
  uint8_t bits = range.getBits();
  if (bits > 0) {
    uint32_t mod = 1 << (32 - bits);
    result.sin4.sin_addr.s_addr = result.sin4.sin_addr.s_addr + htonl(dns_random(mod));
  }
  else {
    result.sin4.sin_addr.s_addr = dns_random_uint32();
  }

  return result;
}

static void replaceEDNSClientSubnet(vector<uint8_t>& packet, const Netmask& ecsRange)
{
  /* the last 4 bytes of the packet are the IPv4 address */
  ComboAddress rnd = getRandomAddressFromRange(ecsRange);
  uint32_t addr = rnd.sin4.sin_addr.s_addr;

  const auto packetSize = packet.size();
  if (packetSize < sizeof(addr)) {
    return;
  }

  memcpy(&packet.at(packetSize - sizeof(addr)), &addr, sizeof(addr));
}

static void replaceSourceIPInProxyProtocolPayload(std::vector<uint8_t>& packet, const Netmask& range)
{
  /* the first 12 bytes of the packet are the Proxy Protocol magic, then one byte for version and command,
   one byte for protocol, 2 bytes for length, then the 4 bytes of the source IPv4 address */
  constexpr size_t position = 12 + 1 + 1 + 2;
  ComboAddress rnd = getRandomAddressFromRange(range);
  uint32_t addr = rnd.sin4.sin_addr.s_addr;

  const auto packetSize = packet.size();
  if (packetSize < position + sizeof(addr)) {
    return;
  }

  memcpy(&packet.at(position), &addr, sizeof(addr));
}

static void sendPackets(const vector<std::unique_ptr<Socket>>& sockets, const vector<vector<uint8_t>* >& packets, uint32_t qps, ComboAddress dest, const std::optional<Netmask>& range, bool ecs, bool proxyProtocol)
{
  unsigned int burst=100;
  const auto nsecPerBurst=1*(unsigned long)(burst*1000000000.0/qps);
  struct timespec nsec;
  nsec.tv_sec=0;
  nsec.tv_nsec=0;
  int count=0;
  unsigned int nBursts=0;
  DTime dt;
  dt.set();

  struct Unit {
    struct msghdr msgh;
    struct iovec iov;
    cmsgbuf_aligned cbuf;
  };

  for(const auto& p : packets) {
    count++;

    Unit u;

    if (range) {
      if (ecs) {
        replaceEDNSClientSubnet(*p, *range);
      }
      else if (proxyProtocol) {
        replaceSourceIPInProxyProtocolPayload(*p, *range);
      }
    }

    fillMSGHdr(&u.msgh, &u.iov, nullptr, 0, (char*)&(*p)[0], p->size(), &dest);

    auto socketHandle = sockets[count % sockets.size()]->getHandle();
    ssize_t sendmsgRet = sendmsg(socketHandle, &u.msgh, 0);
    if (sendmsgRet != 0) {
      if (sendmsgRet < 0) {
        unixDie("sendmsg");
      }
    }

    if(!(count%burst)) {
      nBursts++;
      // Calculate the time in nsec we need to sleep to the next burst.
      // If this is negative, it means that we are not achieving the requested
      // target rate, in which case we skip the sleep.
      int toSleep = nBursts*nsecPerBurst - 1000*dt.udiffNoReset();
      if (toSleep > 0) {
        nsec.tv_nsec = toSleep;
        nanosleep(&nsec, 0);
      }
    }
  }
}

static void usage(po::options_description &desc) {
  cerr<<"Syntax: calidns [OPTIONS] QUERY_FILE DESTINATION INITIAL_QPS HITRATE"<<endl;
  cerr<<desc<<endl;
}

namespace {
  void parseQueryFile(const std::string& queryFile, vector<std::shared_ptr<vector<uint8_t>>>& unknown, bool useRangeFromFile, bool wantRecursion, bool addECS, bool addProxyProtocol)
{
  const ComboAddress emptyAddr("0.0.0.0");
  const ComboAddress localAddr("127.0.0.1");
  const Netmask emptyNetmask("0.0.0.0/32");
  ifstream ifs(queryFile);
  string line;
  std::vector<std::string> fields;
  fields.reserve(3);

  while (getline(ifs, line)) {
    vector<uint8_t> packet;
    DNSPacketWriter::optvect_t ednsOptions;
    boost::trim(line);
    if (line.empty() || line.at(0) == '#') {
      continue;
    }

    fields.clear();
    stringtok(fields, line, "\t ");
    if ((useRangeFromFile && fields.size() < 3) || fields.size() < 2) {
      cerr<<"Skipping invalid line '"<<line<<", it does not contain enough values"<<endl;
      continue;
    }

    const std::string& qname = fields.at(0);
    const std::string& qtype = fields.at(1);
    std::string subnet;

    if (useRangeFromFile) {
      subnet = fields.at(2);
    }

    DNSPacketWriter packetWriter(packet, DNSName(qname), DNSRecordContent::TypeToNumber(qtype));
    packetWriter.getHeader()->rd = wantRecursion;
    packetWriter.getHeader()->id = dns_random_uint16();

    if (addECS) {
      EDNSSubnetOpts opt;
      opt.setSource(subnet.empty() ? emptyNetmask : Netmask(subnet));
      ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
    }

    if (!ednsOptions.empty() || (packetWriter.getHeader()->id % 2) != 0) {
      packetWriter.addOpt(1500, 0, EDNSOpts::DNSSECOK, ednsOptions);
      packetWriter.commit();
    }

    if (addProxyProtocol) {
      auto payload = makeProxyHeader(false, subnet.empty() ? emptyAddr : ComboAddress(subnet), localAddr, {});
      packet.insert(packet.begin(), payload.begin(), payload.end());
    }

    unknown.emplace_back(std::make_shared<vector<uint8_t>>(std::move(packet)));
  }

  shuffle(unknown.begin(), unknown.end(), pdns::dns_random_engine());
}
}

static std::pair<int, std::optional<Netmask>> handleRange(const po::variables_map& options, bool beQuiet)
{
  std::optional<Netmask> range;
  if (options.count("ecs") || options.count("proxy-protocol")) {
    try {
      if (options.count("ecs")) {
        range = Netmask(options["ecs"].as<string>());
      }
      else {
        range = Netmask(options["proxy-protocol"].as<string>());
      }

      if (range && !range->empty()) {
        if (!range->isIPv4()) {
          cerr<<"Only IPv4 ranges are supported for ECS and Proxy Protocol at the moment!"<<endl;
          return {EXIT_FAILURE, range};
        }

        if (!beQuiet) {
          if (options.count("ecs")) {
            cout<<"Adding ECS option to outgoing queries with random addresses from the "<<range->toString()<<" range"<<endl;
          }
          else {
            cout<<"Adding a Proxy Protocol payload in front of outgoing queries with random source IP addresses from the "<<range->toString()<<" range"<<endl;
          }
        }
      }
    }
    catch (const NetmaskException& exp) {
      if (options.count("ecs")) {
        cerr<<"Error while parsing the ECS netmask: "<<exp.reason<<endl;
      }
      else {
        cerr<<"Error while parsing the Proxy Protocol netmask: "<<exp.reason<<endl;
      }
      return {EXIT_FAILURE, range};
    }
  }
  return {0, range};
}

static void sendThread(bool beQuiet)
{
  double bestQPS = 0.0;
  double bestPerfectQPS = 0.0;
  std::vector<std::vector<uint8_t>*> toSend;

  for (qps = qpsstart;;) {
    double seconds=1;
    if (!beQuiet) {
      cout<<"Aiming at "<<qps<< "qps (RD="<<wantRecursion<<") for "<<seconds<<" seconds at cache hitrate "<<100.0*hitrate<<"%";
    }
    unsigned int misses = (1-hitrate) * qps * seconds;
    unsigned int total = qps * seconds;
    if (misses == 0) {
      misses = 1;
    }
    if (!beQuiet) {
      cout<<", need "<<misses<<" misses, "<<total<<" queries, have "<<unknown.size()<<" unknown left!"<<endl;
    }

    if (misses > unknown.size()) {
      cerr<<"Not enough queries remaining (need at least "<<misses<<" and got "<<unknown.size()<<", please add more to the query file), exiting."<<endl;
      return EXIT_FAILURE;
    }
    toSend.reserve(total);
    unsigned int n;

    for (n = 0; n < misses; ++n) {
      auto ptr = unknown.back();
      unknown.pop_back();
      toSend.push_back(ptr.get());
      known.push_back(ptr);
    }
    for (;n < total; ++n) {
      toSend.push_back(known[dns_random(known.size())].get());
    }

    shuffle(toSend.begin(), toSend.end(), pdns::dns_random_engine());
    for (size_t idx = 0; idx < numberOfWorkers; idx++) {
      auto& metrics = workerMetrics.at(idx);
      metrics.recvCounter.store(0);
      metrics.recvBytes.store(0);
    }

    DTime dt;
    dt.set();

    sendPackets(*sockets, toSend, qps, dest, range, addECS, addProxyProtocol);
    toSend.clear();
  }


/*
  New plan. Set cache hit percentage, which we achieve on a per second basis.
  So we start with 10000 qps for example, and for 90% cache hit ratio means
  we take 1000 unique queries and each send them 10 times.

  We then move the 1000 unique queries to the 'known' pool.

  For the next second, say 20000 qps, we know we are going to need 2000 new queries,
  so we take 2000 from the unknown pool. Then we need 18000 cache hits. We can get 1000 from
  the known pool, leaving us down 17000. Or, we have 3000 in total now and we need 2000. We simply
  repeat the 3000 mix we have ~7 times. The 2000 can now go to the known pool too.

  For the next second, say 30000 qps, we'll need 3000 cache misses, which we get from
  the unknown pool. To this we add 3000 queries from the known pool. Next up we repeat this batch 5
  times.

  In general the algorithm therefore is:

  1) Calculate number of cache misses required, get them from the unknown pool
  2) Move those to the known pool
  3) Fill up to amount of queries we need with random picks from the known pool

*/

int main(int argc, char** argv)
try
{
  po::options_description desc("Options");
  desc.add_options()
    ("help,h", "Show this helpful message")
    ("version", "Show the version number")
    ("ecs", po::value<string>(), "Add EDNS Client Subnet option to outgoing queries using random addresses from the specified range (IPv4 only)")
    ("ecs-from-file", "Read IP or subnet values from the query file and add them as EDNS Client Subnet options to outgoing queries")
    ("proxy-protocol", po::value<string>(), "Send a Proxy Protocol payload in front of outgoing queries using random addresses from the specified range (IPv4 only) as the initial source IP")
    ("proxy-protocol-from-file", "Read IP or subnet values from the query file and use them as the source IP in Proxy Protocol payloads in front of outgoing queries")
    ("increment", po::value<float>()->default_value(1.1),  "Set the factor to increase the QPS load per run")
    ("maximum-qps", po::value<uint32_t>(), "Stop incrementing once this rate has been reached, to provide a stable load")
    ("minimum-success-rate", po::value<double>()->default_value(0), "Stop the test as soon as the success rate drops below this value, in percent")
    ("plot-file", po::value<string>(), "Write results to the specific file")
    ("quiet", "Whether to run quietly, outputting only the maximum QPS reached. This option is mostly useful when used with --minimum-success-rate")
    ("want-recursion", "Set the Recursion Desired flag on queries");
  po::options_description alloptions;
  po::options_description hidden("hidden options");
  hidden.add_options()
    ("query-file", po::value<string>(), "File with queries")
    ("destination", po::value<string>(), "Destination address")
    ("initial-qps", po::value<uint32_t>(), "Initial number of queries per second")
    ("hitrate", po::value<double>(), "Aim this percent cache hitrate");

  alloptions.add(desc).add(hidden);
  po::positional_options_description p;
  p.add("query-file", 1);
  p.add("destination", 1);
  p.add("initial-qps", 1);
  p.add("hitrate", 1);

  po::variables_map options;

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), options);
  po::notify(options);

  if (options.count("help")) {
    usage(desc);
    return EXIT_SUCCESS;
  }

  if (options.count("version")) {
    cerr<<"calidns "<<VERSION<<endl;
    return EXIT_SUCCESS;
  }

  if (!(options.count("query-file") && options.count("destination") && options.count("initial-qps") && options.count("hitrate"))) {
    usage(desc);
    return EXIT_FAILURE;
  }

  float increment = 1.1;
  try {
    increment = options["increment"].as<float>();
  }
  catch (...) {
  }

  bool wantRecursion = options.count("want-recursion");
  bool useECSFromFile = options.count("ecs-from-file");
  bool addECS = useECSFromFile || options.count("ecs");
  bool useProxyProtocolFromFile = options.count("proxy-protocol-from-file");
  bool addProxyProtocol = useProxyProtocolFromFile || options.count("proxy-protocol");
  bool beQuiet = options.count("quiet");
  size_t numberOfWorkers = 1;

  double hitrate = options["hitrate"].as<double>();
  if (hitrate > 100 || hitrate < 0) {
    cerr<<"hitrate must be between 0 and 100, not "<<hitrate<<endl;
    return EXIT_FAILURE;
  }
  hitrate /= 100;
  uint32_t qpsstart = options["initial-qps"].as<uint32_t>();

  uint32_t maximumQps = std::numeric_limits<uint32_t>::max();
  if (options.count("maximum-qps")) {
    maximumQps = options["maximum-qps"].as<uint32_t>();
  }

  double minimumSuccessRate = options["minimum-success-rate"].as<double>();
  if (minimumSuccessRate > 100.0 || minimumSuccessRate < 0.0) {
    cerr<<"Minimum success rate must be between 0 and 100, not "<<minimumSuccessRate<<endl;
    return EXIT_FAILURE;
  }

  if (addECS && addProxyProtocol) {
    cerr<<"Enabling ECS and the Proxy Protocol at the same time, is not supported at the moment!"<<endl;
    return EXIT_FAILURE;
  }

  auto [error, range] = handleRange(options, beQuiet);
  if (error != 0) {
    return error;
  }

#ifdef HAVE_SCHED_SETSCHEDULER
  struct sched_param param{};
  param.sched_priority = 99;
  if (sched_setscheduler(0, SCHED_FIFO, &param) < 0) {
    if (!beQuiet) {
      cerr<<"Unable to set SCHED_FIFO: "<<stringerror()<<endl;
    }
  }
#endif

  reportAllTypes();
  std::vector<std::shared_ptr<vector<uint8_t>>> unknown;
  std::vector<std::shared_ptr<vector<uint8_t>>> known;
  parseQueryFile(options["query-file"].as<string>(), unknown, useECSFromFile || useProxyProtocolFromFile, wantRecursion, addECS, addProxyProtocol);

  if (!beQuiet) {
    cout<<"Generated "<<unknown.size()<<" ready to use queries"<<endl;
  }

  ComboAddress dest;
  try {
    dest = ComboAddress(options["destination"].as<string>(), 53);
  }
  catch (PDNSException &e) {
    cerr<<e.reason<<endl;
    return EXIT_FAILURE;
  }

  auto workerSockets = std::vector<std::shared_ptr<std::vector<std::unique_ptr<Socket>>>>(numberOfWorkers);
  for (size_t workerIdx = 0; workerIdx < numberOfWorkers; workerIdx++) {
    auto& sockets = workerSockets.at(workerIdx);
    sockets = std::make_shared<std::vector<std::unique_ptr<Socket>>>();
    for (int i = 0; i < 24; ++i) {
      auto sock = make_unique<Socket>(dest.sin4.sin_family, SOCK_DGRAM);
      //    sock->connect(dest);
      try {
        setSocketSendBuffer(sock->getHandle(), 2000000);
      }
      catch (const std::exception& e) {
        if (!beQuiet) {
          cerr<<e.what()<<endl;
        }
      }
      try {
        setSocketReceiveBuffer(sock->getHandle(), 2000000);
      }
      catch (const std::exception& e) {
        if (!beQuiet) {
        cerr<<e.what()<<endl;
        }
      }

      sockets->emplace_back(std::move(sock));
    }
  }

  std::vector<WorkerMetrics> workerMetrics(numberOfWorkers);

  {
    auto& metrics = workerMetrics.at(0);
    std::thread receiver(recvThread, workerSockets.at(0), std::ref(metrics));
    receiver.detach();
  }

  uint32_t qps;

  ofstream plot;
  if (options.count("plot-file")) {
    plot.open(options["plot-file"].as<string>());
    if (!plot) {
      cerr<<"Error opening "<<options["plot-file"].as<string>()<<" for writing: "<<stringerror()<<endl;
      return EXIT_FAILURE;
    }
  }

      for (size_t idx = 0; idx < numberOfWorkers; idx++) {
      auto& metrics = workerMetrics.at(idx);
      metrics.recvCounter.store(0);
      metrics.recvBytes.store(0);
    }

  for (size_t idx = 0; idx < numberOfWorkers; idx++) {
    std::thread sender(sendThread, sockets.at(idx));
    sender.join();
  }

    const auto udiff = dt.udiffNoReset();
    const auto realqps = toSend.size()/(udiff/1000000.0);
    if (!beQuiet) {
      cout<<"Achieved "<<realqps<<" qps over "<< udiff/1000000.0<<" seconds"<<endl;
    }

    usleep(50000);
    uint64_t received = 0;
    uint64_t receivedBytes = 0;
    for (size_t idx = 0; idx < numberOfWorkers; idx++) {
      auto& metrics = workerMetrics.at(idx);
      received += metrics.recvCounter.load();
      receivedBytes += metrics.recvBytes.load();
    }

    const auto udiffReceived = dt.udiff();
    const auto realReceivedQPS = received/(udiffReceived/1000000.0);
    double perc=received*100.0/toSend.size();
     if (!beQuiet) {
       cout<<"Received "<<received<<" packets over "<< udiffReceived/1000000.0<<" seconds ("<<perc<<"%, adjusted received rate "<<realReceivedQPS<<" qps)"<<endl;
     }

    if (plot) {
      plot<<qps<<" "<<realqps<<" "<<perc<<" "<<received/(udiff/1000000.0)<<" " << 8*receivedBytes/(udiff/1000000.0)<<endl;
      plot.flush();
    }

    if (qps < maximumQps) {
      qps *= increment;
    }
    else {
      qps = maximumQps;
    }

    if (minimumSuccessRate > 0.0 && perc < minimumSuccessRate) {
      if (beQuiet) {
        cout<<bestQPS<<endl;
      }
      else {
        cout<<"The latest success rate ("<<perc<<") dropped below the minimum success rate of "<<minimumSuccessRate<<", stopping."<<endl;
        cout<<"The final rate reached before failing was "<<bestQPS<<" qps (best rate at 100% was "<<bestPerfectQPS<<" qps)"<<endl;
      }
      break;
    }

    bestQPS = std::max(bestQPS, realReceivedQPS);
    if (perc >= 100.0) {
      bestPerfectQPS = std::max(bestPerfectQPS, realReceivedQPS);
    }
  }

  if (plot) {
    plot.flush();
  }

  // t1.detach();
}
catch (const std::exception& exp)
{
  cerr<<"Fatal error: "<<exp.what()<<endl;
  return EXIT_FAILURE;
}
catch (const NetmaskException& exp)
{
  cerr<<"Fatal error: "<<exp.reason<<endl;
  return EXIT_FAILURE;
}
