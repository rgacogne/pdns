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

struct InternalQuery
{
  InternalQuery()
  {
  }

  InternalQuery(PacketBuffer&& buffer, IDState&& state): d_idstate(std::move(state)), d_buffer(std::move(buffer))
  {
  }

  InternalQuery(InternalQuery&& rhs): d_idstate(std::move(rhs.d_idstate)), d_buffer(std::move(rhs.d_buffer)), d_proxyProtocolPayload(std::move(rhs.d_proxyProtocolPayload)), d_proxyProtocolPayloadAdded(rhs.d_proxyProtocolPayloadAdded)
  {
  }
  InternalQuery& operator=(InternalQuery&& rhs)
  {
    d_idstate = std::move(rhs.d_idstate);
    d_buffer = std::move(rhs.d_buffer);
    d_proxyProtocolPayload = std::move(rhs.d_proxyProtocolPayload);
    d_proxyProtocolPayloadAdded = rhs.d_proxyProtocolPayloadAdded;
    return *this;
  }

  InternalQuery(const InternalQuery& rhs) = delete;
  InternalQuery& operator=(const InternalQuery& rhs) = delete;

  IDState d_idstate;
  PacketBuffer d_buffer;
  std::string d_proxyProtocolPayload;
  bool d_proxyProtocolPayloadAdded{false};
};

struct CrossProtocolQuery 
{
  CrossProtocolQuery()
  {
  }

  CrossProtocolQuery(CrossProtocolQuery&& rhs): query(std::move(rhs.query)), downstream(std::move(rhs.downstream)), cbData(rhs.cbData), responsePipe(rhs.responsePipe)
  {
    rhs.cbData = nullptr;
    rhs.responsePipe = -1;
  }

  InternalQuery query;
  std::shared_ptr<DownstreamState> downstream{nullptr};
  void* cbData{nullptr};
  int responsePipe{-1};
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

  bool passConnectionToThread(std::unique_ptr<ConnectionInfo>&& conn)
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

  bool passCrossProtocolQueryToThread(std::unique_ptr<CrossProtocolQuery>&& cpq)
  {
    if (d_numthreads == 0) {
      throw std::runtime_error("No TCP worker thread yet");
    }

    uint64_t pos = d_pos++;
    auto pipe = d_tcpclientthreads.at(pos % d_numthreads).d_crossProtocolQueryPipe;
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

    TCPWorkerThread(int newConnPipe, int crossProtocolPipe): d_newConnectionPipe(newConnPipe), d_crossProtocolQueryPipe(crossProtocolPipe)
    {
    }

    TCPWorkerThread(TCPWorkerThread&& rhs): d_newConnectionPipe(rhs.d_newConnectionPipe), d_crossProtocolQueryPipe(rhs.d_crossProtocolQueryPipe)
    {
      rhs.d_newConnectionPipe = -1;
      rhs.d_crossProtocolQueryPipe = -1;
    }

    TCPWorkerThread& operator=(TCPWorkerThread&& rhs)
    {
      if (d_newConnectionPipe != -1) {
        close(d_newConnectionPipe);
      }
      if (d_crossProtocolQueryPipe != -1) {
        close(d_crossProtocolQueryPipe);
      }

      d_newConnectionPipe = rhs.d_newConnectionPipe;
      d_crossProtocolQueryPipe = rhs.d_crossProtocolQueryPipe;
      rhs.d_newConnectionPipe = -1;
      rhs.d_crossProtocolQueryPipe = -1;

      return *this;
    }

    TCPWorkerThread(const TCPWorkerThread& rhs) = delete;
    TCPWorkerThread& operator=(const TCPWorkerThread&) = delete;

    ~TCPWorkerThread()
    {
      if (d_newConnectionPipe != -1) {
        close(d_newConnectionPipe);
      }
      if (d_crossProtocolQueryPipe != -1) {
        close(d_crossProtocolQueryPipe);
      }
    }

    int d_newConnectionPipe{-1};
    int d_crossProtocolQueryPipe{-1};
  };

  std::mutex d_mutex;
  std::vector<TCPWorkerThread> d_tcpclientthreads;
  stat_t d_numthreads{0};
  stat_t d_pos{0};
  stat_t d_queued{0};
  const uint64_t d_maxthreads{0};
};

extern std::unique_ptr<TCPClientCollection> g_tcpclientthreads;