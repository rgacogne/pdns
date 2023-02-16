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

#include "config.h"
#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif /* HAVE_NGHTTP2 */

#include "dnsdist-tcp-upstream.hh"

class IncomingHTTP2Connection
{
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data);
  static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data);
  static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);
  static int on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data);
  static void handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static void handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param);

public:
  IncomingHTTP2Connection(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now);
  void handleIO();
  
private:
  bool checkALPN();

  enum class State : uint8_t { doingHandshake, readingProxyProtocolHeader, running };

  class PendingQuery
  {
  public:
    PacketBuffer d_buffer;
    size_t d_queryPos{0};
    bool d_finished{false};
  };

  TCPClientThreadData& d_threadData;
  TCPIOHandler d_handler;
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)> d_session{nullptr, nghttp2_session_del};
  std::unordered_map<int32_t, PendingQuery> d_currentStreams;
  PacketBuffer d_out;
  PacketBuffer d_in;
  size_t d_outPos{0};
  size_t d_inPos{0};
  State d_state{State::doingHandshake};
};
