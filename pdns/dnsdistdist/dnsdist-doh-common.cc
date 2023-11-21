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
#include "dnsdist-doh-common.hh"
#include "dnsdist-rules.hh"

#ifdef HAVE_DNS_OVER_HTTPS

HTTPHeaderRule::HTTPHeaderRule(const std::string& header, const std::string& regex) :
  d_header(toLower(header)), d_regex(regex), d_visual("http[" + header + "] ~ " + regex)
{
}

bool HTTPHeaderRule::matches(const DNSQuestion* dq) const
{
  if (!dq->ids.du) {
    return false;
  }

  const auto& headers = dq->ids.du->getHTTPHeaders();
  for (const auto& header : headers) {
    if (header.first == d_header) {
      return d_regex.match(header.second);
    }
  }
  return false;
}

string HTTPHeaderRule::toString() const
{
  return d_visual;
}

HTTPPathRule::HTTPPathRule(std::string path) :
  d_path(std::move(path))
{
}

bool HTTPPathRule::matches(const DNSQuestion* dq) const
{
  if (!dq->ids.du) {
    return false;
  }

  const auto path = dq->ids.du->getHTTPPath();
  return d_path == path;
}

string HTTPPathRule::toString() const
{
  return "url path == " + d_path;
}

HTTPPathRegexRule::HTTPPathRegexRule(const std::string& regex) :
  d_regex(regex), d_visual("http path ~ " + regex)
{
}

bool HTTPPathRegexRule::matches(const DNSQuestion* dq) const
{
  if (!dq->ids.du) {
    return false;
  }

  return d_regex.match(dq->ids.du->getHTTPPath());
}

string HTTPPathRegexRule::toString() const
{
  return d_visual;
}

void DOHFrontend::rotateTicketsKey(time_t now)
{
  return d_tlsContext.rotateTicketsKey(now);
}

void DOHFrontend::loadTicketsKeys(const std::string& keyFile)
{
  return d_tlsContext.loadTicketsKeys(keyFile);
}

std::string DOHFrontend::getNextTicketsKeyRotation() const
{
  return d_tlsContext.getNextTicketsKeyRotation();
}

size_t DOHFrontend::getTicketsKeysCount()
{
  return d_tlsContext.getTicketsKeysCount();
}

void DOHFrontend::reloadCertificates()
{
  d_tlsContext.setupTLS();
}

void DOHFrontend::setup()
{
  if (isHTTPS()) {
    if (!d_tlsContext.setupTLS()) {
      throw std::runtime_error("Error setting up TLS context for DoH listener on '" + d_tlsContext.d_addr.toStringWithPort());
    }
  }
}

#endif /* HAVE_DNS_OVER_HTTPS */
