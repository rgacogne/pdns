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
#include "config.h"

#include "reuseport-policies.hh"

#if defined(HAVE_EBPF)
#include <linux/bpf.h>
#include "ext/libbpf/libbpf.h"
#endif

#include "bpf-utils.hh"
#include "iputils.hh"

namespace pdns::reuseport::policies
{
bool setRandomPolicy([[maybe_unused]] int socketDesc, [[maybe_unused]] uint32_t numberOfSockets)
{
#if defined(HAVE_BPF_FUNC_GET_PRANDOM_U32) && defined(SO_ATTACH_REUSEPORT_EBPF)
  #warning compiling reuseport policy random
  const bpf_insn randomReusePortPolicy[] = {
#include "reuseport-policy-random.ebpf.hh"
  };
  auto program = pdns::bpf::utils::loadBPFProgram(randomReusePortPolicy, sizeof(randomReusePortPolicy));
  if (SSetsockopt(socketDesc, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, program.getHandle()) != 0) {
    // SSetsockopt will actually throw on errors so don't bother doing too much work here
    return false;
  }
  return true;
#else
#warning NOT compiling reuseport policy random
  return false;
#endif
}
}
