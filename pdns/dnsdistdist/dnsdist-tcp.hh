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

struct ConnectionInfo
{
  ConnectionInfo(ClientState* cs_): cs(cs_), fd(-1)
  {
  }
  ConnectionInfo(ConnectionInfo&& rhs): remote(rhs.remote), cs(rhs.cs), fd(rhs.fd)
  {
    rhs.cs = nullptr;
    rhs.fd = -1;
  }

  ConnectionInfo(const ConnectionInfo& rhs) = delete;
  ConnectionInfo& operator=(const ConnectionInfo& rhs) = delete;

  ConnectionInfo& operator=(ConnectionInfo&& rhs)
  {
    remote = rhs.remote;
    cs = rhs.cs;
    rhs.cs = nullptr;
    fd = rhs.fd;
    rhs.fd = -1;
    return *this;
  }

  ~ConnectionInfo()
  {
    if (fd != -1) {
      close(fd);
      fd = -1;
    }

    if (cs) {
      --cs->tcpCurrentConnections;
    }
  }

  ComboAddress remote;
  ClientState* cs{nullptr};
  int fd{-1};
};

class TCPClientCollection {
public:
  TCPClientCollection(size_t maxThreads);

  int getThread()
  {
    if (d_numthreads == 0) {
      throw std::runtime_error("No TCP worker thread yet");
    }

    uint64_t pos = d_pos++;
    ++d_queued;
    return d_tcpclientthreads.at(pos % d_numthreads).d_newConnectionPipe;
  }

  bool passQueryToThread(std::unique_ptr<ConnectionInfo>&& conn)
  { 
    if (d_numthreads == 0) {
      throw std::runtime_error("No TCP worker thread yet");
    }

    uint64_t pos = d_pos++;
    auto pipe = d_tcpclientthreads.at(pos % d_numthreads).d_newConnectionPipe;
    auto tmp = conn.release();

    if (write(pipe, &tmp, sizeof(tmp)) != sizeof(tmp)) {
      delete tmp;
      tmp = nullptr;
      return false;
    }
    ++d_queued;
    return true;
  }

  bool hasReachedMaxThreads() const
  {
    return d_numthreads >= d_maxthreads;
  }

  uint64_t getThreadsCount() const
  {
    return d_numthreads;
  }

  uint64_t getQueuedCount() const
  {
    return d_queued;
  }

  void decrementQueuedCount()
  {
    --d_queued;
  }

  void addTCPClientThread();

private:
  struct TCPWorkerThread
  {
    TCPWorkerThread()
    {
    }

    TCPWorkerThread(int newConnPipe): d_newConnectionPipe(newConnPipe)
    {
    }

    ~TCPWorkerThread()
    {
      if (d_newConnectionPipe != -1) {
        close(d_newConnectionPipe);
      }
    }

    int d_newConnectionPipe{-1};
  };

  std::mutex d_mutex;
  std::vector<TCPWorkerThread> d_tcpclientthreads;
  stat_t d_numthreads{0};
  stat_t d_pos{0};
  stat_t d_queued{0};
  const uint64_t d_maxthreads{0};
};

extern std::unique_ptr<TCPClientCollection> g_tcpclientthreads;
