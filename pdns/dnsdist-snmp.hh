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
#pragma once

#include "snmp-agent.hh"

namespace dnsdist::snmp
{
class DNSDistSNMPAgent;

struct DNSDistSNMPConfig
{
  static void enableTraps()
  {
    if (isEnabled()) {
      s_snmpTrapsEnabled = true;
    }
  }

  static bool isEnabled()
  {
    return s_snmpAgent != nullptr;
  }

  static bool areTrapsEnabled()
  {
    return isEnabled() && s_snmpTrapsEnabled;
  }

  static DNSDistSNMPAgent& getAgent()
  {
    if (!isEnabled()) {
      throw std::runtime_error("Trying to get an unitialized SNMP agent");
    }
    return *s_snmpAgent;
  }

  static void enable(const std::string& name, const std::string& daemonSocket);
  static void start();

private:
  static std::unique_ptr<DNSDistSNMPAgent> s_snmpAgent;
  static bool s_snmpTrapsEnabled;
};
}

#include "dnsdist.hh"

namespace dnsdist::snmp
{
class DNSDistSNMPAgent: public SNMPAgent
{
public:
  DNSDistSNMPAgent(const std::string& name, const std::string& daemonSocket);
  bool sendBackendStatusChangeTrap(const DownstreamState&);
  bool sendCustomTrap(const std::string& reason);
  bool sendDNSTrap(const DNSQuestion&, const std::string& reason="");
};
}
