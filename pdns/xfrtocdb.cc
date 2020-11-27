
#include <iostream>
#include <unordered_set>

#include "axfr-retriever.hh"
#include "cdb.hh"

/* BEGIN Needed because of deeper dependencies */
#include "arguments.hh"
#include "statbag.hh"
StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
/* END Needed because of deeper dependencies */

int main(int argc, char**argv)
{
  if (argc != 3) {
    cerr<<"Usage: <zone to AXFR> <IP address of master>"<<endl;
    return 2;
  }

  const DNSName zone(argv[1]);
  const ComboAddress master(argv[2]);

  std::unordered_set<DNSName> names;

  try {
    ComboAddress local = master.isIPv4() ? ComboAddress("0.0.0.0") : ComboAddress("::");
    TSIGTriplet tt;
    AXFRRetriever axfr(master, zone, tt, &local);
    Resolver::res_t nop;
    vector<DNSRecord> chunk;
    while (axfr.getChunk(nop, &chunk)) {
      for (const auto& dr : chunk) {
        names.insert(dr.d_name);
      }
    }
  }
  catch (const PDNSException& e) {
    cerr<<"PDNS Error during AXFR: "<<e.reason<<endl;
    return 1;
  }
  catch (const std::exception& e) {
    cerr<<"Error during AXFR: "<<e.what()<<endl;
    return 1;
  }

  char db[] = "/tmp/test_cdb.XXXXXX";
  {
    int fd = mkstemp(db);
    if (fd == -1) {
      cerr<<"Error opening file: "<<errno<<endl;
      return 1;
    }

    CDBWriter writer(fd);
    for (const auto& name : names) {
      writer.addEntry(name.toStringNoDot(), "");
    }
    writer.close();
  }
  cout<<"written "<<names.size()<<" names to "<<std::string(db)<<endl;
  return 0;
}

