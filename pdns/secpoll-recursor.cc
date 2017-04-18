#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "secpoll-recursor.hh"
#include "syncres.hh"
#include "logger.hh"
#include "arguments.hh"
#include "version.hh"
#include "validate-recursor.hh"

#include <stdint.h>
#ifndef PACKAGEVERSION 
#define PACKAGEVERSION getPDNSVersion()
#endif

uint32_t g_security_status;
string g_security_message;

void doSecPoll(time_t* last_secpoll)
{
  if(::arg()["security-poll-suffix"].empty())
    return;

  string pkgv(PACKAGEVERSION);
  struct timeval now;
  gettimeofday(&now, 0);
  SyncRes sr(now);
  if (g_dnssecmode != DNSSECMode::Off)
    sr.setDoDNSSEC(true);
  vector<DNSRecord> ret;

  string version = "recursor-" +pkgv;
  string qstring(version.substr(0, 63)+ ".security-status."+::arg()["security-poll-suffix"]);

  if(*qstring.rbegin()!='.')
    qstring+='.';

  boost::replace_all(qstring, "+", "_");
  boost::replace_all(qstring, "~", "_");

  vState state = Indeterminate;
  DNSName query(qstring);
  int res=sr.beginResolve(query, QType(QType::TXT), 1, ret);

  if (g_dnssecmode != DNSSECMode::Off && res) {
    /*ResolveContext ctx;
      state = validateRecords(ctx, ret);*/
    state = sr.getValidationState();
  }

  if(state == Bogus) {
    L<<Logger::Error<<"Could not retrieve security status update for '" +pkgv+ "' on '"<<query<<"', DNSSEC validation result was Bogus!"<<endl;
    if(g_security_status == 1) // If we were OK, go to unknown
      g_security_status = 0;
    return;
  }

  if(!res && !ret.empty()) {
    string content=ret.begin()->d_content->getZoneRepresentation();
    if(!content.empty() && content[0]=='"' && content[content.size()-1]=='"') {
      content=content.substr(1, content.length()-2);
    }
      
    pair<string, string> split = splitField(content, ' ');
    
    g_security_status = std::stoi(split.first);
    g_security_message = split.second;

    *last_secpoll=now.tv_sec;
  }
  else {
    if(pkgv.find("0.0."))
      L<<Logger::Warning<<"Could not retrieve security status update for '" +pkgv+ "' on '"<<query<<"', RCODE = "<< RCode::to_s(res)<<endl;
    else
      L<<Logger::Warning<<"Ignoring response for security status update, this a non-release version."<<endl;

    if(g_security_status == 1) // it was ok, now it is unknown
      g_security_status = 0;
    if(res == RCode::NXDomain) // if we had NXDOMAIN, keep on trying more more frequently
      *last_secpoll=now.tv_sec; 
  }

  if(g_security_status == 2) {
    L<<Logger::Error<<"PowerDNS Security Update Recommended: "<<g_security_message<<endl;
  }
  else if(g_security_status == 3) {
    L<<Logger::Error<<"PowerDNS Security Update Mandatory: "<<g_security_message<<endl;
  }
}
