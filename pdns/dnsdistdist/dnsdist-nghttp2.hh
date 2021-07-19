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

class DoHClientCollection
{
public:
  DoHClientCollection(size_t maxThreads);

  bool passCrossProtocolQueryToThread(std::unique_ptr<CrossProtocolQuery>&& cpq)
  {
    if (d_numberOfThreads == 0) {
      throw std::runtime_error("No DoH worker thread yet");
    }

    uint64_t pos = d_pos++;
    auto pipe = d_clientThreads.at(pos % d_numberOfThreads).d_crossProtocolQueryPipe;
    auto tmp = cpq.release();

    if (write(pipe, &tmp, sizeof(tmp)) != sizeof(tmp)) {
      delete tmp;
      tmp = nullptr;
      return false;
    }

    return true;
  }

  bool hasReachedMaxThreads() const
  {
    return d_numberOfThreads >= d_maxthreads;
  }

  uint64_t getThreadsCount() const
  {
    return d_numberOfThreads;
  }

  void addThread();

private:
  struct DoHWorkerThread;

  std::mutex d_mutex;
  std::vector<DoHWorkerThread> d_clientThreads;
  stat_t d_numberOfThreads{0};
  stat_t d_pos{0};
  const uint64_t d_maxThreads{0};
};

extern std::unique_ptr<DoHClientCollection> g_dohClientThreads;
extern std::atomic<uint64_t> g_dohStatesDumpRequested{0};

void sendHTTP2Query();
