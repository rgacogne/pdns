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

#if defined(HAVE_EBPF)
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#endif

#include "bpf-utils.hh"

namespace pdns::bpf::utils
{
static __u64 ptr_to_u64(const void* ptr)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
  return (__u64)(unsigned long)ptr;
}

static int bpf_prog_load(enum bpf_prog_type prog_type,
                         const struct bpf_insn* insns, size_t prog_len,
                         const char* license, int kern_version)
{
  char log_buf[65535];
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = prog_type;
  attr.insns = ptr_to_u64((void*)insns);
  attr.insn_cnt = static_cast<int>(prog_len / sizeof(struct bpf_insn));
  attr.license = ptr_to_u64((void*)license);
  attr.log_buf = ptr_to_u64(log_buf);
  attr.log_size = sizeof(log_buf);
  attr.log_level = 1;
  /* assign one field outside of struct init to make sure any
   * padding is zero initialized
   */
  attr.kern_version = kern_version;

  long res = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  if (res == -1) {
    if (errno == ENOSPC) {
      /* not enough space in the log buffer */
      attr.log_level = 0;
      attr.log_size = 0;
      attr.log_buf = ptr_to_u64(nullptr);
      res = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
      if (res != -1) {
        return res;
      }
    }
    throw std::runtime_error("Error loading BPF program: (" + stringerror() + "):\n" + std::string(log_buf));
  }
  return res;
}

FDWrapper loadBPFProgram(const bpf_insn* filter, size_t filterSize)
{
  auto descriptor = FDWrapper(bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                                            filter,
                                            filterSize,
                                            "GPL",
                                            0));
  if (descriptor.getHandle() == -1) {
    throw std::runtime_error("error loading BPF filter: " + stringerror());
  }
  return descriptor;
}
}
