
#include <netinet/in.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <sys/socket.h>

#include "iputils.hh"
#include "misc.hh"
#include "dnsrecords.hh"
#include "dolog.hh"
#include "statbag.hh"

StatBag S;

bool g_syslog{true};
bool g_console{true};

static uint16_t makeQuery(vector<uint8_t>& spacket, DNSName qname, uint16_t qtype)
{
  uint16_t id = random();

  DNSPacketWriter pw(spacket, qname, qtype);
  pw.getHeader()->id=id;
  pw.getHeader()->rd=0;
  pw.commit();

  return id;
}

static int sendFromTo(const ComboAddress& src, const ComboAddress& dest, const char* packet, int len)
{
  int s = SSocket(AF_INET, SOCK_DGRAM, 0);
  SSetsockopt(s, IPPROTO_IP , IP_TRANSPARENT, 1);
  SBind(s, src);
  int ret= sendto(s, packet, len, 0, (struct sockaddr*)&dest, dest.getSocklen());
  close(s);
  return ret;
}

static std::vector<ComboAddress> generateSources(const std::string& sourceNetwork, unsigned long nbAddrs)
{
  std::vector<ComboAddress> result;
  result.reserve(nbAddrs);

  uint8_t net = 0;
  uint8_t host = 1;

  for (unsigned long idx = 0; idx < nbAddrs; idx++) {

    result.push_back(ComboAddress(sourceNetwork + "." + std::to_string(net) + "." + std::to_string(host)));
    cerr<<"Generated "<<result.back().toString()<<endl;
    if (host == 255) {
      net++;
      host = 1;
    } else {
      host++;
    }
  }

  return result;
}

int main(int argc, char** argv)
try
{
  if (argc != 5) {
    cerr<<"Usage :"<<argv[0]<<" <qname> <destination> <source prefix (/16, e.g. 192.168) to spoof> <number of addresses to spoof>"<<endl;
    return EXIT_FAILURE;
  }

  DNSName qname(argv[1]);
  ComboAddress dest(argv[2]);
  std::string sourceNetwork(argv[3]);
  unsigned long nbAddresses = std::stoul(argv[4]);

  std::vector<ComboAddress> sources= generateSources(sourceNetwork, nbAddresses);

  vector<uint8_t> packet;

  unsigned long idx = 0;
  for (;;) {
    makeQuery(packet, qname, QType::A);
    sendFromTo(sources[idx], dest, reinterpret_cast<const char*>(packet.data()), packet.size());
    if ((idx + 1) >= sources.size()) {
      idx = 0;
    } else {
      idx++;
    }
  }

  return EXIT_SUCCESS;
}
catch(const std::exception& e)
{
  cerr<<"Error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
