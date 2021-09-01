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

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "dnsname.hh"
#include "iputils.hh"

struct SVCRecordParameters
{
  SVCRecordParameters()
  {
  }

  std::set<uint16_t> mandatoryParams;
  std::vector<std::string> alpns;
  std::vector<ComboAddress> ipv4hints;
  std::vector<ComboAddress> ipv6hints;
  std::vector<std::pair<uint16_t, std::string>> additionalParams;
  std::string ech;
  DNSName target;
  std::optional<uint16_t> port{std::nullopt};
  uint16_t priority{0};
  bool noDefaultAlpn{false};
};

bool generateSVCPayload(std::vector<uint8_t>& payload, uint16_t priority, const DNSName& target, const std::set<uint16_t>& mandatoryParams, const std::vector<std::string>& alpns, bool noDefaultAlpn, std::optional<uint16_t> port, const std::string& ech, const std::vector<ComboAddress>& ipv4hints, const std::vector<ComboAddress>& ipv6hints, const std::vector<std::pair<uint16_t, std::string>>& additionalParams);

bool generateSVCPayload(std::vector<uint8_t>& payload, const SVCRecordParameters& parameters);
