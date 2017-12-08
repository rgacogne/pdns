
#include "iputils.hh"
#include "misc.hh"
#include "dns.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include "statbag.hh"

StatBag S;

int main(int argc, char **argv)
{
  if(argc < 2) {
    cerr<<"This program reads DNS queries and responses from PCAP files and outputs a query file usable by calidns."<<endl;
    cerr<<"Usage: "<<argv[0]<<" <PCAP file> [ <PCAP file> ...]"<<endl;
    exit(EXIT_FAILURE);
  }

  for (size_t idx = 1; idx < static_cast<size_t>(argc); idx++) {
    PcapPacketReader pr(argv[idx]);

    while (pr.getUDPPacket()) {
      const auto dh = reinterpret_cast<const dnsheader*>(pr.d_payload);

      if (!dh->qdcount) {
        continue;
      }

      if (pr.d_len <= sizeof(dnsheader)) {
        continue;
      }

      try {
        uint16_t qtype, qclass;
        DNSName qname(reinterpret_cast<const char*>(pr.d_payload), pr.d_len, sizeof(dnsheader), false, &qtype, &qclass);
        std::cout<<qname.toString()<<" "<<QType(qtype).getName()<<std::endl;
      }
      catch(const std::exception& e) {
        continue;
      }
    }
  }

  exit(EXIT_SUCCESS);
}
