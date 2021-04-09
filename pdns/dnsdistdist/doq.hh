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

#include "iputils.hh"
#include "libssl.hh"

struct DOQFrontend
{
  DOQFrontend()
  {
  }

  TLSConfig d_tlsConfig;
  TLSErrorCounters d_tlsCounters;
  ComboAddress d_local;

  time_t getTicketsKeyRotationDelay() const
  {
    return d_tlsConfig.d_ticketsKeyRotationDelay;
  }

#if 0
//#ifndef HAVE_DNS_OVER_QUIC
  void setup()
  {
  }

  void reloadCertificates()
  {
  }

  void rotateTicketsKey(time_t now)
  {
  }

  void loadTicketsKeys(const std::string& keyFile)
  {
  }

  void handleTicketsKeyRotation()
  {
  }

  time_t getNextTicketsKeyRotation() const
  {
    return 0;
  }

  size_t getTicketsKeysCount() const
  {
    size_t res = 0;
    return res;
  }

#else
  void setup();
  void reloadCertificates();

  void rotateTicketsKey(time_t now);
  void loadTicketsKeys(const std::string& keyFile);
  void handleTicketsKeyRotation();
  time_t getNextTicketsKeyRotation() const;
  size_t getTicketsKeysCount() const;
#endif /* HAVE_DNS_OVER_QUIC */
};
