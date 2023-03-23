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

#include "dnsdist-tcp-upstream.hh"

class IncomingHTTP2Connection :  public IncomingTCPConnectionState
{
public:
  using StreamID = int32_t;

  class PendingQuery
  {
  public:
    enum class Method : uint8_t { Unknown, Get, Post };

    PacketBuffer d_buffer;
    PacketBuffer d_response;
    std::string d_path;
    std::string d_scheme;
    std::string d_host;
    std::string d_queryString;
    std::string d_sni;
    std::string d_contentTypeOut;
    std::unique_ptr<HeadersMap> d_headers;
    size_t d_queryPos{0};
    uint32_t d_statusCode{0};
    Method d_method{Method::Unknown};
  };

  IncomingHTTP2Connection(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now);
  ~IncomingHTTP2Connection() = default;
  void handleIO() override;
  void handleResponse(const struct timeval& now, TCPResponse&& response) override;
  void notifyIOError(const struct timeval& now, TCPResponse&& response) override;
  void restoreContext(uint32_t streamID, PendingQuery&& context);

private:
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, StreamID stream_id, const uint8_t* data, size_t len, void* user_data);
  static int on_stream_close_callback(nghttp2_session* session, StreamID stream_id, uint32_t error_code, void* user_data);
  static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);
  static int on_begin_headers_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data);
  static void handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static void handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param);

  IOState sendResponse(const struct timeval& now, TCPResponse&& response) override;
  bool forwardViaUDPFirst() const override
  {
    return true;
  }
  void restoreDOHUnit(std::unique_ptr<DOHUnitInterface>&&) override;
  std::unique_ptr<DOHUnitInterface> getDOHUnit(uint32_t streamID) override;

  void stopIO();
  bool isIdle() const;
  uint32_t getConcurrentStreamsCount() const;
  void updateIO(IOState newState, FDMultiplexer::callbackfunc_t callback);
  void watchForRemoteHostClosingConnection();
  void handleIOError();
  bool sendResponse(StreamID streamID, uint16_t responseCode, const HeadersMap& customResponseHeaders, const std::string& contentType = "", bool addContentType = true);
  void handleIncomingQuery(PendingQuery&& query, StreamID streamID);
  bool checkALPN();
  void readHTTPData();
  void handleConnectionReady();
  boost::optional<struct timeval> getIdleClientReadTTD(struct timeval now) const;

  std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)> d_session{nullptr, nghttp2_session_del};
  std::unordered_map<StreamID, PendingQuery> d_currentStreams;
  PacketBuffer d_out;
  PacketBuffer d_in;
  size_t d_outPos{0};
  bool d_connectionDied{false};
};

class NGHTTP2Headers
{
public:
  static void addStaticHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& valueKey);
  static void addDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string_view& value);
  static void addCustomDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& name, const std::string_view& value);
};

#endif /* HAVE_NGHTTP2 */
