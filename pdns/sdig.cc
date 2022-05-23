#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cmath>
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "misc.hh"
#include "proxy-protocol.hh"
#include "sstuff.hh"
#include "statbag.hh"
#include <boost/array.hpp>

#ifdef HAVE_LIBCURL
#include "minicurl.hh"
#endif

#include "tcpiohandler.hh"

StatBag S;

// Vars below used by tcpiohandler.cc
bool g_verbose = true;
bool g_syslog = false;

static bool hidettl = false;

static string ttl(uint32_t ttl)
{
  if (hidettl)
    return "[ttl]";
  else
    return std::to_string(ttl);
}

static void usage()
{
  cerr << "sdig" << endl;
  cerr << "Syntax: sdig IP-ADDRESS-OR-DOH-URL PORT QNAME QTYPE "
          "[dnssec] [ednssubnet SUBNET/MASK] [hidesoadetails] [hidettl] [recurse] [showflags] "
          "[tcp] [dot] [insecure] [fastOpen] [subjectName name] [caStore file] [tlsProvider openssl|gnutls] "
          "[xpf XPFDATA] [class CLASSNUM] "
          "[proxy UDP(0)/TCP(1) SOURCE-IP-ADDRESS-AND-PORT DESTINATION-IP-ADDRESS-AND-PORT] "
          "[dumpluaraw] [opcode OPNUM]"
       << endl;
}

static const string nameForClass(QClass qclass, uint16_t qtype)
{
  if (qtype == QType::OPT)
    return "IN";

  return qclass.toString();
}

static std::unordered_set<uint16_t> s_expectedIDs;

static void fillPacket(vector<uint8_t>& packet, const string& q, const string& t,
                       bool dnssec, const boost::optional<Netmask> ednsnm,
                       bool recurse, uint16_t xpfcode, uint16_t xpfversion,
                       uint64_t xpfproto, char* xpfsrc, char* xpfdst,
                       QClass qclass, uint8_t opcode, uint16_t qid)
{
  DNSPacketWriter pw(packet, DNSName(q), DNSRecordContent::TypeToNumber(t), qclass, opcode);

  if (dnssec || ednsnm || getenv("SDIGBUFSIZE")) {
    char* sbuf = getenv("SDIGBUFSIZE");
    int bufsize;
    if (sbuf)
      bufsize = atoi(sbuf);
    else
      bufsize = 2800;
    DNSPacketWriter::optvect_t opts;
    if (ednsnm) {
      EDNSSubnetOpts eo;
      eo.source = *ednsnm;
      opts.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(eo));
    }

    pw.addOpt(bufsize, 0, dnssec ? EDNSOpts::DNSSECOK : 0, opts);
    pw.commit();
  }

  if (xpfcode) {
    ComboAddress src(xpfsrc), dst(xpfdst);
    pw.startRecord(g_rootdnsname, xpfcode, 0, QClass::IN, DNSResourceRecord::ADDITIONAL);
    // xpf->toPacket(pw);
    pw.xfr8BitInt(xpfversion);
    pw.xfr8BitInt(xpfproto);
    pw.xfrCAWithoutPort(xpfversion, src);
    pw.xfrCAWithoutPort(xpfversion, dst);
    pw.xfrCAPort(src);
    pw.xfrCAPort(dst);
    pw.commit();
  }

  if (recurse) {
    pw.getHeader()->rd = true;
  }

  pw.getHeader()->id = htons(qid);
}

static void printReply(const string& reply, bool showflags, bool hidesoadetails, bool dumpluaraw)
{
  MOADNSParser mdp(false, reply);
  if (!s_expectedIDs.count(ntohs(mdp.d_header.id))) {
    cout << "ID " << ntohs(mdp.d_header.id) << " was not expected, this response was not meant for us!"<<endl;
  }
  s_expectedIDs.erase(ntohs(mdp.d_header.id));

  cout << "Reply to question for qname='" << mdp.d_qname.toString()
       << "', qtype=" << DNSRecordContent::NumberToType(mdp.d_qtype) << endl;
  cout << "Rcode: " << mdp.d_header.rcode << " ("
       << RCode::to_s(mdp.d_header.rcode) << "), RD: " << mdp.d_header.rd
       << ", QR: " << mdp.d_header.qr;
  cout << ", TC: " << mdp.d_header.tc << ", AA: " << mdp.d_header.aa
       << ", opcode: " << mdp.d_header.opcode << endl;

  for (MOADNSParser::answers_t::const_iterator i = mdp.d_answers.begin();
       i != mdp.d_answers.end(); ++i) {
    cout << i->first.d_place - 1 << "\t" << i->first.d_name.toString() << "\t"
         << nameForClass(i->first.d_class, i->first.d_type) << "\t"
         << DNSRecordContent::NumberToType(i->first.d_type);
    if (dumpluaraw) {
      cout<<"\t"<< makeLuaString(i->first.d_content->serialize(DNSName(), true))<<endl;
      continue;
    }
    if (i->first.d_class == QClass::IN) {
      if (i->first.d_type == QType::RRSIG) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " "
             << parts[1] << " " << parts[2] << " " << parts[3]
             << " [expiry] [inception] [keytag] " << parts[7] << " ...\n";
        continue;
      }
      if (!showflags && i->first.d_type == QType::NSEC3) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " [flags] "
             << parts[2] << " " << parts[3] << " " << parts[4];
        for (vector<string>::iterator iter = parts.begin() + 5;
             iter != parts.end(); ++iter)
          cout << " " << *iter;
        cout << "\n";
        continue;
      }
      if (i->first.d_type == QType::DNSKEY) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " "
             << parts[1] << " " << parts[2] << " ...\n";
        continue;
      }
      if (i->first.d_type == QType::SOA && hidesoadetails) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " "
             << parts[1] << " [serial] " << parts[3] << " " << parts[4] << " "
             << parts[5] << " " << parts[6] << "\n";
        continue;
      }
    }
    cout << "\t" << ttl(i->first.d_ttl) << "\t"
         << i->first.d_content->getZoneRepresentation() << "\n";
  }

  EDNSOpts edo;
  if (getEDNSOpts(mdp, &edo)) {
    //    cerr<<"Have "<<edo.d_options.size()<<" options!"<<endl;
    for (vector<pair<uint16_t, string>>::const_iterator iter = edo.d_options.begin();
         iter != edo.d_options.end(); ++iter) {
      if (iter->first == EDNSOptionCode::ECS) { // 'EDNS subnet'
        EDNSSubnetOpts reso;
        if (getEDNSSubnetOptsFromString(iter->second, &reso)) {
          cerr << "EDNS Subnet response: " << reso.source.toString()
               << ", scope: " << reso.scope.toString()
               << ", family = " << reso.scope.getNetwork().sin4.sin_family
               << endl;
        }
      } else if (iter->first == EDNSOptionCode::PADDING) {
        cerr << "EDNS Padding size: " << (iter->second.size()) << endl;
      } else {
        cerr << "Have unknown option " << (int)iter->first << endl;
      }
    }
  }
}

int main(int argc, char** argv)
try {
  /* default timeout of 10s */
  struct timeval timeout{10,0};
  bool dnssec = false;
  bool recurse = false;
  bool tcp = false;
  bool showflags = false;
  bool hidesoadetails = false;
  bool doh = false;
  bool dot = false;
  bool fastOpen = false;
  bool insecureDoT = false;
  bool fromstdin = false;
  boost::optional<Netmask> ednsnm;
  uint16_t xpfcode = 0, xpfversion = 0, xpfproto = 0;
  char *xpfsrc = NULL, *xpfdst = NULL;
  QClass qclass = QClass::IN;
  uint8_t opcode = 0;
  string proxyheader;
  string subjectName;
  string caStore;
  string tlsProvider = "openssl";
  bool dumpluaraw = false;
  size_t chr = 0;
  size_t qps = 0;
  size_t runTime = 0;
  boost::optional<bool> verbose;

  for (int i = 1; i < argc; i++) {
    if ((string)argv[i] == "--help") {
      usage();
      exit(EXIT_SUCCESS);
    }

    if ((string)argv[i] == "--version") {
      cerr << "sdig " << VERSION << endl;
      exit(EXIT_SUCCESS);
    }
  }

  if (argc < 5) {
    usage();
    exit(EXIT_FAILURE);
  }

  reportAllTypes();

  if (argc > 5) {
    for (int i = 5; i < argc; i++) {
      if (strcmp(argv[i], "dnssec") == 0)
        dnssec = true;
      else if (strcmp(argv[i], "recurse") == 0)
        recurse = true;
      else if (strcmp(argv[i], "showflags") == 0)
        showflags = true;
      else if (strcmp(argv[i], "hidesoadetails") == 0)
        hidesoadetails = true;
      else if (strcmp(argv[i], "hidettl") == 0)
        hidettl = true;
      else if (strcmp(argv[i], "tcp") == 0)
        tcp = true;
      else if (strcmp(argv[i], "dot") == 0)
        dot = true;
      else if (strcmp(argv[i], "insecure") == 0)
        insecureDoT = true;
      else if (strcmp(argv[i], "fastOpen") == 0)
        fastOpen = true;
      else if (strcmp(argv[i], "ednssubnet") == 0) {
        if (argc < i + 2) {
          cerr << "ednssubnet needs an argument" << endl;
          exit(EXIT_FAILURE);
        }
        ednsnm = Netmask(argv[++i]);
      }
      else if (strcmp(argv[i], "xpf") == 0) {
        if (argc < i + 6) {
          cerr << "xpf needs five arguments" << endl;
          exit(EXIT_FAILURE);
        }
        xpfcode = atoi(argv[++i]);
        xpfversion = atoi(argv[++i]);
        xpfproto = atoi(argv[++i]);
        xpfsrc = argv[++i];
        xpfdst = argv[++i];
      }
      else if (strcmp(argv[i], "class") == 0) {
        if (argc < i+2) {
          cerr << "class needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        qclass = atoi(argv[++i]);
      }
      else if (strcmp(argv[i], "opcode") == 0) {
        if (argc < i+2) {
          cerr << "opcode needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        opcode = atoi(argv[++i]);
      }
      else if (strcmp(argv[i], "subjectName") == 0) {
        if (argc < i + 2) {
          cerr << "subjectName needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        subjectName = argv[++i];
      }
      else if (strcmp(argv[i], "caStore") == 0) {
        if (argc < i + 2) {
          cerr << "caStore needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        caStore = argv[++i];
      }
      else if (strcmp(argv[i], "tlsProvider") == 0) {
        if (argc < i + 2) {
          cerr << "tlsProvider needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        tlsProvider = argv[++i];
      }
      else if (strcmp(argv[i], "proxy") == 0) {
        if(argc < i+4) {
          cerr<<"proxy needs three arguments"<<endl;
          exit(EXIT_FAILURE);
        }
        bool ptcp = atoi(argv[++i]);
        ComboAddress src(argv[++i]);
        ComboAddress dest(argv[++i]);
        proxyheader = makeProxyHeader(ptcp, src, dest, {});
      }
      else if (strcmp(argv[i], "dumpluaraw") == 0) {
        dumpluaraw = true;
      }
      else if (strcmp(argv[i], "chr") == 0) {
        if (argc < i+2) {
          cerr << "chr needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        chr = atoi(argv[++i]);
        if (chr > 100) {
          cerr<<"the chr value needs to be between 0 and 100"<<endl;
          exit(EXIT_FAILURE);
        }
      }
      else if (strcmp(argv[i], "qps") == 0) {
        if (argc < i+2) {
          cerr << "qps needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        qps = atoi(argv[++i]);
        if (qps == 0) {
          cerr<<"the qps value needs to be greater than 0"<<endl;
          exit(EXIT_FAILURE);
        }
      }
      else if (strcmp(argv[i], "runtime") == 0) {
        if (argc < i+2) {
          cerr << "runtime needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        runTime = atoi(argv[++i]);
        if (runTime == 0) {
          cerr<<"the runtime value needs to be greater than 0"<<endl;
          exit(EXIT_FAILURE);
        }
      }
      else if (strcmp(argv[i], "verbose") == 0) {
        verbose = true;
      }
      else {
        cerr << argv[i] << ": unknown argument" << endl;
        exit(EXIT_FAILURE);
      }
    }
  }

  if (dot) {
    tcp = true;
  }

#ifndef HAVE_DNS_OVER_TLS
  if (dot) {
    cerr << "DoT requested but not compiled in" << endl;
    exit(EXIT_FAILURE);
  }
#endif

  string reply;
  ComboAddress dest;
  if (*argv[1] == 'h') {
    doh = true;
  } else if(strcmp(argv[1], "stdin") == 0) {
    fromstdin = true;
  } else {
    dest = ComboAddress(argv[1] + (*argv[1] == '@'), atoi(argv[2]));
  }

  string name = string(argv[3]);
  string type = string(argv[4]);

  size_t totalNumberOfQueries = 1;
  if (qps > 0 && runTime > 0) {
    totalNumberOfQueries = qps * runTime;
    if (!verbose) {
      verbose = false;
    }
  }
  else {
    if (!verbose) {
      verbose = true;
    }
  }

  size_t numberOfQueriesSent = 0;
  std::vector<int> latencies;
  latencies.reserve(totalNumberOfQueries);

  uint64_t questionIdx = 0;
  vector<pair<string, string>> questions;
  if (name == "-" && type == "-") {
    string line;
    while (getline(std::cin, line)) {
      auto fields = splitField(line, ' ');

      questions.emplace_back(fields.first, fields.second);
    }
  } else {
    questions.reserve(totalNumberOfQueries);

    for (size_t secondsCounter = 0; secondsCounter < runTime; secondsCounter++) {
      double hitRate = chr / 100.0;
      unsigned int misses = std::round(static_cast<double>(qps) * (1.0 - hitRate));
      unsigned int total = qps;
      size_t idx = 0;
      for (idx = 0; idx < misses; idx++) {
        questions.emplace_back(std::to_string(rand()) + "." + name, type);
      }
      for (; idx < total; idx++) {
        questions.emplace_back(name, type);
      }
    }
  }

  DTime dt;
  if (doh) {
#ifdef HAVE_LIBCURL
    vector<uint8_t> packet;
    MiniCurl mc;
    MiniCurl::MiniCurlHeaders mch;
    mch.emplace("Content-Type", "application/dns-message");
    mch.emplace("Accept", "application/dns-message");
    // FIXME: how do we use proxyheader here?
    while (numberOfQueriesSent < totalNumberOfQueries) {
      dt.set();
      packet.clear();
      s_expectedIDs.insert(0);
      //cerr<<"preparing to send "<<questions.at(questionIdx % questions.size()).first<<endl;
      fillPacket(packet, questions.at(questionIdx % questions.size()).first, questions.at(questionIdx % questions.size()).second, dnssec, ednsnm, recurse, xpfcode, xpfversion,
                 xpfproto, xpfsrc, xpfdst, qclass, opcode, 0);
      ++questionIdx;
      string question(packet.begin(), packet.end());
      reply = mc.postURL(argv[1], question, mch, timeout.tv_sec, fastOpen);
      if (*verbose) {
        printReply(reply, showflags, hidesoadetails, dumpluaraw);
      }
      numberOfQueriesSent++;
      auto elapsed = dt.udiffNoReset();
      latencies.push_back(elapsed);

      if (qps) {
        unsigned int wait = 1000000/qps;
        if (elapsed > 0 && static_cast<unsigned int>(elapsed) < wait) {
          usleep(wait-elapsed);
        }
      }
    }
#else
    throw PDNSException("please link sdig against libcurl for DoH support");
#endif
  } else if (fromstdin) {
    std::istreambuf_iterator<char> begin(std::cin), end;
    reply = string(begin, end);

    ComboAddress source, destination;
    bool wastcp;
    bool proxy = false;
    std::vector<ProxyProtocolValue> ignoredValues;
    ssize_t offset = parseProxyHeader(reply, proxy, source, destination, wastcp, ignoredValues);
    if (offset && proxy) {
      cout<<"proxy "<<(wastcp ? "tcp" : "udp")<<" headersize="<<offset<<" source="<<source.toStringWithPort()<<" destination="<<destination.toStringWithPort()<<endl;
      reply = reply.substr(offset);
    }

    if (tcp) {
      reply = reply.substr(2);
    }

    if (*verbose) {
      printReply(reply, showflags, hidesoadetails, dumpluaraw);
    }
  } else if (tcp) {
    std::shared_ptr<TLSCtx> tlsCtx{nullptr};
    if (dot) {
      TLSContextParameters tlsParams;
      tlsParams.d_provider = tlsProvider;
      tlsParams.d_validateCertificates = !insecureDoT;
      tlsParams.d_caStore = caStore;
      tlsCtx = getTLSContext(tlsParams);
    }
    uint16_t counter = 0;
    Socket sock(dest.sin4.sin_family, SOCK_STREAM);
    sock.setNonBlocking();
    setTCPNoDelay(sock.getHandle()); // disable NAGLE, which does not play nicely with delayed ACKs
    TCPIOHandler handler(subjectName, false, sock.releaseHandle(), timeout, tlsCtx, time(nullptr));
    handler.connect(fastOpen, dest, timeout);
    // we are writing the proxyheader inside the TLS connection. Is that right?
    if (proxyheader.size() > 0 && handler.write(proxyheader.data(), proxyheader.size(), timeout) != proxyheader.size()) {
      throw PDNSException("tcp write failed");
    }

    while (numberOfQueriesSent < totalNumberOfQueries) {
      dt.set();
      vector<uint8_t> packet;
      s_expectedIDs.insert(counter);
      fillPacket(packet, questions.at(counter % questions.size()).first, questions.at(counter % questions.size()).second, dnssec, ednsnm, recurse, xpfcode,
                 xpfversion, xpfproto, xpfsrc, xpfdst, qclass, opcode, counter);
      counter++;

      // Prefer to do a single write, so that fastopen can send all the data on SYN
      uint16_t len = packet.size();
      string question;
      question.reserve(sizeof(len) + packet.size());
      question.push_back(static_cast<char>(len >> 8));
      question.push_back(static_cast<char>(len & 0xff));
      question.append(packet.begin(), packet.end());
      if (handler.write(question.data(), question.size(), timeout) != question.size()) {
        throw PDNSException("tcp write failed");
      }

      if (handler.read((char *)&len, sizeof(len), timeout) != sizeof(len)) {
        throw PDNSException("tcp read failed");
      }
      len = ntohs(len);
      reply.resize(len);
      if (handler.read(&reply[0], len, timeout) != len) {
        throw PDNSException("tcp read failed");
      }
      if (*verbose) {
        printReply(reply, showflags, hidesoadetails, dumpluaraw);
      }
      numberOfQueriesSent++;

      auto elapsed = dt.udiffNoReset();
      latencies.push_back(elapsed);

      if (qps > 0) {
        unsigned int wait = 1000000/qps;
        if (elapsed > 0 && static_cast<unsigned int>(elapsed) < wait) {
          usleep(wait-elapsed);
        }
      }
    }
  } else // udp
  {
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    vector<uint8_t> packet;
    while (numberOfQueriesSent < totalNumberOfQueries) {
      s_expectedIDs.insert(0);
      dt.set();
    fillPacket(packet, questions.at(questionIdx % questions.size()).first, questions.at(questionIdx % questions.size()).second, dnssec, ednsnm, recurse, xpfcode, xpfversion,
               xpfproto, xpfsrc, xpfdst, qclass, opcode, 0);
    questionIdx++;
    string question(packet.begin(), packet.end());
    question = proxyheader + question;
    sock.sendTo(question, dest);
    int result = waitForData(sock.getHandle(), timeout.tv_sec, timeout.tv_usec);
    if (result < 0)
      throw std::runtime_error("Error waiting for data: " + stringerror());
    if (!result)
      throw std::runtime_error("Timeout waiting for data");
    sock.recvFrom(reply, dest);
    if (verbose) {
      printReply(reply, showflags, hidesoadetails, dumpluaraw);
    }
    numberOfQueriesSent++;

    auto elapsed = dt.udiffNoReset();
    latencies.push_back(elapsed);

    if (qps > 0) {
      unsigned int wait = 1000000/qps;
      if (elapsed > 0 && static_cast<unsigned int>(elapsed) < wait) {
        usleep(wait-elapsed);
      }
    }
    }
  }

  if (runTime > 0) {
    cout<<"========================="<<endl;
    cout<<"=        SUMMARY        ="<<endl;
    cout<<"========================="<<endl;
    cerr<<"Sent "<<numberOfQueriesSent<<" queries over "<<runTime<<" seconds at "<<qps<<" queries per second, using a "<<chr<<" cache hit ratio target"<<endl;
    cerr<<"Received "<<latencies.size()<<" responses over "<<numberOfQueriesSent<<", success rate is "<<((100.0*latencies.size()/numberOfQueriesSent))<<"%"<<endl;
    std::sort(latencies.begin(), latencies.end());
    cerr<<"Minimum latency is "<<latencies.at(0)<<" µs"<<endl;
    cerr<<"Maxixmum latency is "<<latencies.at(latencies.size()-1)<<" µs"<<endl;
    cerr<<"Mean latency is "<<latencies.at((latencies.size()-1)/2)<<" µs"<<endl;
    uint64_t total = 0;
    for (const auto& value : latencies) {
      total += value;
    }
    cerr<<"Average latency is "<<(total/latencies.size())<<" µs"<<endl;

    auto percentileIndex = static_cast<size_t>(std::floor((latencies.size() * 95.0) / 100.0)) - 1;
    percentileIndex = std::min(percentileIndex, latencies.size() - 1);
    cerr<<"95 percentile latency is "<<latencies.at(percentileIndex)<<" µs"<<endl;

    percentileIndex = static_cast<size_t>(std::floor((latencies.size() * 99.0) / 100.0)) - 1;
    percentileIndex = std::min(percentileIndex, latencies.size() - 1);
    cerr<<"99 percentile latency is "<<latencies.at(percentileIndex)<<" µs"<<endl;
  }

} catch (std::exception& e) {
  cerr << "Fatal: " << e.what() << endl;
} catch (PDNSException& e) {
  cerr << "Fatal: " << e.reason << endl;
}
