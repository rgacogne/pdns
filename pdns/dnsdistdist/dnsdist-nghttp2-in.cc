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

#include "base64.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsparser.hh"

class IncomingDoHCrossProtocolContext : public CrossProtocolContext
{
public:
  IncomingDoHCrossProtocolContext(IncomingHTTP2Connection::PendingQuery&& query, std::shared_ptr<IncomingHTTP2Connection> connection, IncomingHTTP2Connection::StreamID streamID): CrossProtocolContext(std::move(query.d_buffer)), d_connection(connection), d_query(std::move(query))
  {
  }

  std::optional<std::string> getHTTPPath() const override
  {
    return d_query.d_path;
  }

  std::optional<std::string> getHTTPScheme() const override
  {
    return d_query.d_scheme;
  }

  std::optional<std::string> getHTTPHost() const override
  {
    return d_query.d_host;
  }

  std::optional<std::string> getHTTPQueryString() const override
  {
    return d_query.d_queryString;
  }

  std::optional<HeadersMap> getHTTPHeaders() const override
  {
    if (!d_query.d_headers) {
      return std::nullopt;
    }
    return *d_query.d_headers;
  }

  void handleResponse(PacketBuffer&& response, InternalQueryState&& state) override
  {
    auto conn = d_connection.lock();
    if (!conn) {
      /* the connection has been closed in the meantime */
      return;
    }
  }

  void handleTimeout() override
  {
    auto conn = d_connection.lock();
    if (!conn) {
      /* the connection has been closed in the meantime */
      return;
    }
  }

  ~IncomingDoHCrossProtocolContext() override
  {
  }

private:
  std::weak_ptr<IncomingHTTP2Connection> d_connection;
  IncomingHTTP2Connection::PendingQuery d_query;
  IncomingHTTP2Connection::StreamID d_streamID{-1};
};

IncomingHTTP2Connection::IncomingHTTP2Connection(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): IncomingTCPConnectionState(std::move(ci), threadData, now)
{
  nghttp2_session_callbacks* cbs = nullptr;
  if (nghttp2_session_callbacks_new(&cbs) != 0) {
    throw std::runtime_error("Unable to create a callback object for a new incoming HTTP/2 session");
  }
  std::unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks*)> callbacks(cbs, nghttp2_session_callbacks_del);
  cbs = nullptr;

  nghttp2_session_callbacks_set_send_callback(callbacks.get(), send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), on_stream_close_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks.get(), on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_error_callback2(callbacks.get(), on_error_callback);

  nghttp2_session* sess = nullptr;
  if (nghttp2_session_server_new(&sess, callbacks.get(), this) != 0) {
    throw std::runtime_error("Coult not allocate a new incoming HTTP/2 session");
  }

  d_session = std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)>(sess, nghttp2_session_del);
  sess = nullptr;
}

bool IncomingHTTP2Connection::checkALPN()
{
  constexpr std::array<uint8_t, 2> h2{'h', '2'};
  auto protocols = d_handler.getNextProtocol();
  if (protocols.size() == h2.size() && memcmp(protocols.data(), h2.data(), h2.size()) == 0) {
    return true;
  }
  vinfolog("DoH connection from %s expected h2 ALPN, got %s", d_ci.remote.toStringWithPort(), std::string(protocols.begin(), protocols.end()));
  return false;
}

void IncomingHTTP2Connection::handleConnectionReady()
{
  constexpr std::array<nghttp2_settings_entry, 1> iv{
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
  };
  auto ret = nghttp2_submit_settings(d_session.get(), NGHTTP2_FLAG_NONE, iv.data(), iv.size());
  if (ret != 0) {
    throw std::runtime_error("Fatal error: " + std::string(nghttp2_strerror(ret)));
  }
  ret = nghttp2_session_send(d_session.get());
  if (ret != 0) {
    throw std::runtime_error("Fatal error: " + std::string(nghttp2_strerror(ret)));
  }
}

void IncomingHTTP2Connection::handleIO()
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  IOState iostate = IOState::Done;
  struct timeval now;
  gettimeofday(&now, nullptr);

  try {
    if (maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
      vinfolog("Terminating DoH connection from %s because it reached the maximum TCP connection duration", d_ci.remote.toStringWithPort());
      stopIO();
      d_connectionDied = true;
      return;
    }

    if (d_state == State::doingHandshake) {
      iostate = d_handler.tryHandshake();
      if (iostate == IOState::Done) {
        handleHandshakeDone(now);
        if (d_handler.isTLS()) {
          if (!checkALPN()) {
            d_connectionDied = true;
            stopIO();
          }
        }

        if (expectProxyProtocolFrom(d_ci.remote)) {
          d_state = IncomingTCPConnectionState::State::readingProxyProtocolHeader;
          d_buffer.resize(s_proxyProtocolMinimumHeaderSize);
          d_proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
        }
        else {
          d_state = State::waitingForQuery;
          handleConnectionReady();
        }
      }
    }

    if (d_state == IncomingTCPConnectionState::State::readingProxyProtocolHeader) {
      auto status = handleProxyProtocolPayload();
      if (status == ProxyProtocolResult::Done) {
        d_currentPos = 0;
        d_proxyProtocolNeed = 0;
        d_buffer.clear();
        d_state = State::waitingForQuery;
        handleConnectionReady();
      }
      else if (status == ProxyProtocolResult::Error) {
        d_connectionDied = true;
        stopIO();
      }
    }

    if (d_state == State::waitingForQuery) {
      readHTTPData();
    }

    if (!d_connectionDied) {
      auto shared = std::dynamic_pointer_cast<IncomingHTTP2Connection>(shared_from_this());
      if (nghttp2_session_want_read(d_session.get())) {
        cerr<<"wants read"<<endl;
        d_ioState->add(IOState::NeedRead, &handleReadableIOCallback, shared, boost::none);
      }
      if (nghttp2_session_want_write(d_session.get())) {
        cerr<<"wants write"<<endl;
        d_ioState->add(IOState::NeedWrite, &handleWritableIOCallback, shared, boost::none);
      }
    }
  }
  catch (const std::exception& e) {
    vinfolog("Exception when processing IO for incoming DoH connection from %s: %s", d_ci.remote.toStringWithPort(), e.what());
    cerr<<e.what()<<endl;
    throw;
  }
}

ssize_t IncomingHTTP2Connection::send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<" with "<<length<<endl;
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  bool bufferWasEmpty = conn->d_out.empty();
  conn->d_out.insert(conn->d_out.end(), data, data + length);

  if (bufferWasEmpty) {
    try {
      auto state = conn->d_handler.tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
      if (state == IOState::Done) {
        cerr<<"wrote "<<conn->d_out.size()<<" directly"<<endl;
        conn->d_out.clear();
        conn->d_outPos = 0;
        conn->stopIO();
        if (!conn->isIdle()) {
          conn->updateIO(IOState::NeedRead, handleReadableIOCallback);
        }
        else {
          conn->watchForRemoteHostClosingConnection();
        }
      }
      else {
        conn->updateIO(state, handleWritableIOCallback);
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception while trying to write (send) to incoming HTTP connection: %s", e.what());
      conn->handleIOError();
    }
  }

  return length;
}

static const std::unordered_map<std::string, std::string> s_constants{
  {"200-value", "200"},
  {"method-name", ":method"},
  {"method-value", "POST"},
  {"scheme-name", ":scheme"},
  {"scheme-value", "https"},
  {"authority-name", ":authority"},
  {"x-forwarded-for-name", "x-forwarded-for"},
  {"path-name", ":path"},
  {"content-length-name", "content-length"},
  {"status-name", ":status"},
  {"location-name", "location"},
  {"accept-name", "accept"},
  {"accept-value", "application/dns-message"},
  {"cache-control-name", "cache-control"},
  {"content-type-name", "content-type"},
  {"content-type-value", "application/dns-message"},
  {"user-agent-name", "user-agent"},
  {"user-agent-value", "nghttp2-" NGHTTP2_VERSION "/dnsdist"},
  {"x-forwarded-port-name", "x-forwarded-port"},
  {"x-forwarded-proto-name", "x-forwarded-proto"},
  {"x-forwarded-proto-value-dns-over-udp", "dns-over-udp"},
  {"x-forwarded-proto-value-dns-over-tcp", "dns-over-tcp"},
  {"x-forwarded-proto-value-dns-over-tls", "dns-over-tls"},
  {"x-forwarded-proto-value-dns-over-http", "dns-over-http"},
  {"x-forwarded-proto-value-dns-over-https", "dns-over-https"},
};

static const std::string s_pathHeaderName(":path");
static const std::string s_methodHeaderName(":method");
static const std::string s_xForwardedForHeaderName("x-forwarded-for");

void NGHTTP2Headers::addStaticHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& valueKey)
{
  const auto& name = s_constants.at(nameKey);
  const auto& value = s_constants.at(valueKey);

  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void NGHTTP2Headers::addCustomDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& name, const std::string_view& value)
{
  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.data())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.data())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void NGHTTP2Headers::addDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string_view& value)
{
  const auto& name = s_constants.at(nameKey);
  NGHTTP2Headers::addCustomDynamicHeader(headers, name, value);
}

IOState IncomingHTTP2Connection::sendResponse(const struct timeval& now, TCPResponse&& response)
{
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  assert(response.d_streamID.has_value() == true);
  d_currentStreams.at(response.d_streamID.value()).d_buffer = std::move(response.d_buffer);
  sendResponse(response.d_streamID.value(), 200, d_ci.cs->dohFrontend->d_customResponseHeaders);
  return IOState::Done;
}

bool IncomingHTTP2Connection::sendResponse(IncomingHTTP2Connection::StreamID streamID, uint16_t responseCode, const HeadersMap& customResponseHeaders, const std::string& contentType, bool addContentType)
{
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  /* if data_prd is not NULL, it provides data which will be sent in subsequent DATA frames. In this case, a method that allows request message bodies (https://tools.ietf.org/html/rfc7231#section-4) must be specified with :method key (e.g. POST). This function does not take ownership of the data_prd. The function copies the members of the data_prd. If data_prd is NULL, HEADERS have END_STREAM set.
   */
  nghttp2_data_provider data_provider;

  data_provider.source.ptr = this;
  data_provider.read_callback = [](nghttp2_session*, IncomingHTTP2Connection::StreamID stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* cb_data) -> ssize_t {
    cerr<<"in read callback for stream "<<(int)stream_id<<endl;
    auto connection = reinterpret_cast<IncomingHTTP2Connection*>(cb_data);
    auto& obj = connection->d_currentStreams.at(stream_id);
    cerr<<"buffer size is "<<obj.d_buffer.size()<<", position is "<<obj.d_queryPos<<endl;
    size_t toCopy = 0;
    if (obj.d_queryPos < obj.d_buffer.size()) {
      size_t remaining = obj.d_buffer.size() - obj.d_queryPos;
      toCopy = length > remaining ? remaining : length;
      memcpy(buf, &obj.d_buffer.at(obj.d_queryPos), toCopy);
      obj.d_queryPos += toCopy;
    }

    cerr<<"in read callback, returning "<<toCopy<<endl;
    if (obj.d_queryPos >= obj.d_buffer.size()) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      cerr<<"done"<<endl;
    }
    return toCopy;
  };

  const auto& df = d_ci.cs->dohFrontend;
  cerr<<"adding headers"<<endl;
  auto& responseBody = d_currentStreams.at(streamID).d_buffer;

  std::vector<nghttp2_nv> headers;
  for (const auto& [key, value]: customResponseHeaders) {
    NGHTTP2Headers::addCustomDynamicHeader(headers, key, value);
  }

  if (responseCode == 200) {
    NGHTTP2Headers::addStaticHeader(headers, "status-name", "200-value");
    ++df->d_validresponses;
    ++df->d_http2Stats.d_nb200Responses;

    if (addContentType) {
      if (contentType.empty()) {
        NGHTTP2Headers::addStaticHeader(headers, "content-type-key", "content-type-value");
      }
      else {
        NGHTTP2Headers::addDynamicHeader(headers, "content-type-key", contentType);
      }
    }

    if (df->d_sendCacheControlHeaders && responseBody.size() > sizeof(dnsheader)) {
      uint32_t minTTL = getDNSPacketMinTTL(reinterpret_cast<const char*>(responseBody.data()), responseBody.size());
      if (minTTL != std::numeric_limits<uint32_t>::max()) {
        std::string cacheControlValue = "max-age=" + std::to_string(minTTL);
      NGHTTP2Headers::addDynamicHeader(headers, "cache-control-name", cacheControlValue);
      }
    }
  }
  else {
    std::string responseCodeStr = std::to_string(responseCode);
    NGHTTP2Headers::addDynamicHeader(headers, "status-name", responseCodeStr);

    if (responseCode >= 300 && responseCode < 400) {
      NGHTTP2Headers::addDynamicHeader(headers, "content-type-key", "text/html; charset=utf-8");
      NGHTTP2Headers::addDynamicHeader(headers, "location-key", std::string_view(reinterpret_cast<const char*>(responseBody.data()), responseBody.size()));
      static const std::string s_redirectStart{"<!DOCTYPE html><TITLE>Moved</TITLE><P>The document has moved <A HREF=\""};
      static const std::string s_redirectEnd{"\">here</A>"};
      responseBody.reserve(s_redirectStart.size() + responseBody.size() + s_redirectEnd.size());
      responseBody.insert(responseBody.begin(), s_redirectStart.begin(), s_redirectStart.end());
      responseBody.insert(responseBody.end(), s_redirectEnd.begin(), s_redirectEnd.end());
      ++df->d_redirectresponses;
    }
    else {
      ++df->d_errorresponses;
      switch (responseCode) {
      case 400:
        ++df->d_http2Stats.d_nb400Responses;
        break;
      case 403:
        ++df->d_http2Stats.d_nb403Responses;
        break;
      case 500:
        ++df->d_http2Stats.d_nb500Responses;
        break;
      case 502:
        ++df->d_http2Stats.d_nb502Responses;
        break;
      default:
        ++df->d_http2Stats.d_nbOtherResponses;
        break;
      }

      if (!responseBody.empty()) {
        NGHTTP2Headers::addDynamicHeader(headers, "content-type-key", "text/plain; charset=utf-8");
      }
      else {
        static const std::string invalid{"invalid DNS query"};
        static const std::string notAllowed{"dns query not allowed"};
        static const std::string noDownstream{"no downstream server available"};
        static const std::string internalServerError{"Internal Server Error"};

        switch (responseCode) {
        case 400:
          responseBody.insert(responseBody.begin(), invalid.begin(), invalid.end());
          break;
        case 403:
          responseBody.insert(responseBody.begin(), notAllowed.begin(), notAllowed.end());
          break;
        case 502:
          responseBody.insert(responseBody.begin(), noDownstream.begin(), noDownstream.end());
          break;
        case 500:
          /* fall-through */
        default:
          responseBody.insert(responseBody.begin(), internalServerError.begin(), internalServerError.end());
          break;
        }
      }
    }
  }

  const std::string contentLength = std::to_string(responseBody.size());
  NGHTTP2Headers::addDynamicHeader(headers, "content-length-name", contentLength);

  cerr<<"submitting response of size "<<responseBody.size()<<endl;
  auto ret = nghttp2_submit_response(d_session.get(), streamID, headers.data(), headers.size(), &data_provider);
  if (ret != 0) {
    d_currentStreams.erase(streamID);
    vinfolog("Error submitting HTTP response for stream %d: %s", streamID, nghttp2_strerror(ret));
    return false;
  }

  cerr<<"sending data for response of size "<<responseBody.size()<<endl;
  ret = nghttp2_session_send(d_session.get());
  if (ret != 0) {
    d_currentStreams.erase(streamID);
    vinfolog("Error flushing HTTP response for stream %d: %s", streamID, nghttp2_strerror(ret));
    return false;
  }

  cerr<<"out of sendResponse"<<endl;
  return true;
}

static void processForwardedForHeader(const std::unique_ptr<HeadersMap>& headers, ComboAddress& remote)
{
  if (!headers) {
    return;
  }

  auto it = headers->find(s_xForwardedForHeaderName);
  if (it == headers->end()) {
    return;
  }

  std::string_view value = it->second;
  try {
    auto pos = value.rfind(',');
    if (pos != std::string_view::npos) {
      ++pos;
      for (; pos < value.size() && value[pos] == ' '; ++pos)
      {
      }

      if (pos < value.size()) {
        value = value.substr(pos);
      }
    }
    auto newRemote = ComboAddress(std::string(value));
    remote = newRemote;
  }
  catch (const std::exception& e) {
    vinfolog("Invalid X-Forwarded-For header ('%s') received from %s : %s", std::string(value), remote.toStringWithPort(), e.what());
  }
  catch (const PDNSException& e) {
    vinfolog("Invalid X-Forwarded-For header ('%s') received from %s : %s", std::string(value), remote.toStringWithPort(), e.reason);
  }
}

void IncomingHTTP2Connection::handleIncomingQuery(IncomingHTTP2Connection::PendingQuery&& query, IncomingHTTP2Connection::StreamID streamID)
{
  const auto handleImmediateResponse = [this, &query, streamID](uint16_t code, const std::string& reason, PacketBuffer&& response = PacketBuffer()) {
    if (response.empty()) {
      query.d_buffer.clear();
      query.d_buffer.insert(query.d_buffer.begin(), reason.begin(), reason.end());
    }
    else {
      query.d_buffer = std::move(response);
    }
    vinfolog("Sending an immediate %d response to incoming DoH query: %s", code, reason);
    sendResponse(streamID, code, d_ci.cs->dohFrontend->d_customResponseHeaders);
  };

  if (query.d_badRequest) {
    handleImmediateResponse(400, "DoH unable to decode BASE64-URL");
  }


  ++d_ci.cs->dohFrontend->d_http2Stats.d_nbQueries;

  if (d_ci.cs->dohFrontend->d_trustForwardedForHeader) {
    processForwardedForHeader(query.d_headers, d_ci.remote);

    /* second ACL lookup based on the updated address */
    auto& holders = d_threadData.holders;
    if (!holders.acl->match(d_ci.remote)) {
      ++g_stats.aclDrops;
      vinfolog("Query from %s (DoH) dropped because of ACL", d_ci.remote.toStringWithPort());
      handleImmediateResponse(403, "DoH query not allowed because of ACL (with X-Forwarded-For)");
      return;
    }

    if (!d_ci.cs->dohFrontend->d_keepIncomingHeaders) {
      query.d_headers.reset();
    }
  }

  if (query.d_method == PendingQuery::Method::Get) {
    ++d_ci.cs->dohFrontend->d_getqueries;
  }
  else if (query.d_method == PendingQuery::Method::Post) {
    ++d_ci.cs->dohFrontend->d_postqueries;
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  auto processingResult = handleQuery(std::move(query.d_buffer), now, streamID);

  switch (processingResult) {
  case QueryProcessingResult::TooSmall:
    handleImmediateResponse(400, "DoH non-compliant query");
    break;
  case QueryProcessingResult::InvalidHeaders:
    handleImmediateResponse(400, "DoH invalid headers");
    break;
  case QueryProcessingResult::Empty:
    handleImmediateResponse(200, "DoH empty query", std::move(query.d_buffer));
    break;
  case QueryProcessingResult::Dropped:
    handleImmediateResponse(403, "DoH dropped query");
    break;
  case QueryProcessingResult::NoBackend:
    handleImmediateResponse(502, "DoH no backend available");
    return;
  case QueryProcessingResult::Forwarded:
  case QueryProcessingResult::Asynchronous:
  case QueryProcessingResult::SelfAnswered:
    break;
  }
}

int IncomingHTTP2Connection::on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    cerr<<"got headers"<<endl;
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      cerr<<"All headers received"<<endl;
    }
    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
      cerr<<"All headers received - query"<<endl;
    }
    break;
  case NGHTTP2_WINDOW_UPDATE:
    cerr<<"got window update"<<endl;
    break;
  case NGHTTP2_SETTINGS:
    cerr<<"got settings"<<endl;
    cerr<<frame->settings.niv<<endl;
    for (size_t idx = 0; idx < frame->settings.niv; idx++) {
      cerr<<"- "<<frame->settings.iv[idx].settings_id<<" "<<frame->settings.iv[idx].value<<endl;
    }
    break;
  case NGHTTP2_DATA:
    cerr<<"got data"<<endl;
    break;
  }

  if (frame->hd.type == NGHTTP2_GOAWAY) {
    conn->stopIO();
    if (conn->isIdle()) {
      if (nghttp2_session_want_write(conn->d_session.get())) {
        cerr<<"wants write"<<endl;
        conn->d_ioState->add(IOState::NeedWrite, &handleWritableIOCallback, conn, boost::none);
      }
    }
  }

  /* is this the last frame for this stream? */
  else if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    auto streamID = frame->hd.stream_id;
    auto stream = conn->d_currentStreams.find(streamID);
    if (stream != conn->d_currentStreams.end()) {
      cerr<<"got query of size "<<stream->second.d_buffer.size()<<endl;
      conn->handleIncomingQuery(std::move(stream->second), streamID);

      if (conn->isIdle()) {
        conn->stopIO();
        conn->watchForRemoteHostClosingConnection();
      }
    }
    else {
      vinfolog("Stream %d NOT FOUND", streamID);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

int IncomingHTTP2Connection::on_stream_close_callback(nghttp2_session* session, IncomingHTTP2Connection::StreamID stream_id, uint32_t error_code, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  if (error_code == 0) {
    return 0;
  }

  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    /* we don't care, then */
    return 0;
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  auto request = std::move(stream->second);
  conn->d_currentStreams.erase(stream->first);

  // cerr<<"we now have "<<conn->getConcurrentStreamsCount()<<" concurrent connections"<<endl;
  if (conn->isIdle()) {
    // cerr<<"stopping IO"<<endl;
    conn->stopIO();
    conn->watchForRemoteHostClosingConnection();
  }

  return 0;
}

int IncomingHTTP2Connection::on_begin_headers_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  auto insertPair = conn->d_currentStreams.insert({frame->hd.stream_id, PendingQuery()});
  if (!insertPair.second) {
    /* there is a stream ID collision, something is very wrong! */
    vinfolog("Stream ID collision (%d) on connection from %d", frame->hd.stream_id, conn->d_ci.remote.toStringWithPort());
    conn->d_connectionDied = true;
    nghttp2_session_terminate_session(conn->d_session.get(), NGHTTP2_NO_ERROR);
    auto ret = nghttp2_session_send(conn->d_session.get());
    if (ret != 0) {
      vinfolog("Error flushing HTTP response for stream %d from %s: %s", frame->hd.stream_id, conn->d_ci.remote.toStringWithPort(), nghttp2_strerror(ret));
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }
  cerr<<"inserted pending query for "<<frame->hd.stream_id<<endl;
  return 0;
}

static std::optional<PacketBuffer> getPayloadFromPath(const std::string_view& path)
{
  std::optional<PacketBuffer> result{std::nullopt};

  if (path.size() <= 5) {
    return result;
  }

  auto pos = path.find("?dns=");
  if (pos == string::npos) {
    pos = path.find("&dns=");
  }

  if (pos == string::npos) {
    return result;
  }

  // need to base64url decode this
  string sdns(path.substr(pos + 5));
  boost::replace_all(sdns,"-", "+");
  boost::replace_all(sdns,"_", "/");

  // re-add padding that may have been missing
  switch (sdns.size() % 4) {
  case 2:
    sdns.append(2, '=');
    break;
  case 3:
    sdns.append(1, '=');
    break;
  }

  PacketBuffer decoded;
  /* rough estimate so we hopefully don't need a new allocation later */
  /* We reserve at few additional bytes to be able to add EDNS later */
  const size_t estimate = ((sdns.size() * 3) / 4);
  decoded.reserve(estimate);
  if (B64Decode(sdns, decoded) < 0) {
    return result;
  }

  result = std::move(decoded);
  return result;
}

int IncomingHTTP2Connection::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t nameLen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    if (nghttp2_check_header_name(name, nameLen) == 0) {
      vinfolog("Invalid header name");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (nghttp2_check_header_value_rfc9113(value, valuelen) == 0) {
      vinfolog("Invalid header value");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    auto headerMatches = [name, nameLen](const std::string& expected) -> bool {
      return nameLen == expected.size() && memcmp(name, expected.data(), expected.size()) == 0;
    };

    cerr<<"id is "<<frame->hd.stream_id<<endl;
    auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
    if (stream == conn->d_currentStreams.end()) {
      vinfolog("Unable to match the stream ID %d to a known one!", frame->hd.stream_id);
      cerr<<"NOT found"<<endl;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto& query = stream->second;
    auto valueView = std::string_view(reinterpret_cast<const char*>(value), valuelen);
    // cerr<<"got header for "<<frame->hd.stream_id<<":"<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(name), nameLen)<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(value), valuelen)<<endl;
    if (headerMatches(s_pathHeaderName)) {
      if (nghttp2_check_path(value, valuelen) == 0) {
        vinfolog("Invalid path value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      query.d_path = std::string(valueView);
      cerr<<"Got path: "<<query.d_path<<endl;
    }
    else if (headerMatches(s_methodHeaderName)) {
      cerr<<"Got method: "<<valueView<<endl;
      if (nghttp2_check_method(value, valuelen) == 0) {
        vinfolog("Invalid method value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      if (valueView == "GET") {
        query.d_method = PendingQuery::Method::Get;
      }
      else if (valueView == "POST") {
        query.d_method = PendingQuery::Method::Post;
      }
      else {
        vinfolog("Unsupported method value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }

    if (query.d_buffer.empty() && query.d_method == PendingQuery::Method::Get && !query.d_path.empty()) {
      auto payload = getPayloadFromPath(valueView);
      if (payload) {
        cerr<<"Got payload of size "<<payload->size()<<endl;
        query.d_buffer = std::move(*payload);
        cerr<<"buffer size is now "<<query.d_buffer.size();
      }
      else {
        ++conn->d_ci.cs->dohFrontend->d_badrequests;
        cerr<<"unable to get payload"<<endl;
        query.d_badRequest = true;
      }
    }

    if (conn->d_ci.cs->dohFrontend->d_keepIncomingHeaders || (conn->d_ci.cs->dohFrontend->d_trustForwardedForHeader && headerMatches(s_xForwardedForHeaderName))) {
      if (!query.d_headers) {
        query.d_headers = std::make_unique<HeadersMap>();
      }
      query.d_headers->insert({std::string(reinterpret_cast<const char*>(name), nameLen), std::string(valueView)});
    }
  }
  return 0;
}

int IncomingHTTP2Connection::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, IncomingHTTP2Connection::StreamID stream_id, const uint8_t* data, size_t len, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<" with "<<len<<endl;
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
   cerr<<"Got data of size "<<len<<" for stream "<<stream_id<<endl;
  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    vinfolog("Unable to match the stream ID %d to a known one!", stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (len > std::numeric_limits<uint16_t>::max() || (std::numeric_limits<uint16_t>::max() - stream->second.d_buffer.size()) < len) {
    vinfolog("Data frame of size %d is too large for a DNS query (we already have %d)", len, stream->second.d_buffer.size());
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  stream->second.d_buffer.insert(stream->second.d_buffer.end(), data, data + len);

  return 0;
}

int IncomingHTTP2Connection::on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  vinfolog("Error in HTTP/2 connection from %d: %s", conn->d_ci.remote.toStringWithPort(), std::string(msg, len));
  conn->d_connectionDied = true;
  nghttp2_session_terminate_session(conn->d_session.get(), NGHTTP2_NO_ERROR);
  auto ret = nghttp2_session_send(conn->d_session.get());
  if (ret != 0) {
    vinfolog("Error flushing HTTP response on connection from %s: %s", conn->d_ci.remote.toStringWithPort(), nghttp2_strerror(ret));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

void IncomingHTTP2Connection::readHTTPData()
{
  IOStateGuard ioGuard(d_ioState);
  do {
    d_inPos = 0;
    d_in.resize(d_in.size() + 512);
    cerr<<"trying to read "<<d_in.size()<<endl;
    try {
      IOState newState = d_handler.tryRead(d_in, d_inPos, d_in.size(), true);
       cerr<<"got a "<<(int)newState<<" state and "<<d_inPos<<" bytes"<<endl;
      d_in.resize(d_inPos);

      if (d_inPos > 0) {
        /* we got something */
        //std::cerr << d_in.data() << endl;
        auto readlen = nghttp2_session_mem_recv(d_session.get(), d_in.data(), d_inPos);
         cerr<<"nghttp2_session_mem_recv returned "<<readlen<<endl;
        /* as long as we don't require a pause by returning nghttp2_error.NGHTTP2_ERR_PAUSE from a CB,
           all data should be consumed before returning */
        if (readlen < 0 || static_cast<size_t>(readlen) < d_inPos) {
          throw std::runtime_error("Fatal error while passing received data to nghttp2: " + std::string(nghttp2_strerror((int)readlen)));
        }

         cerr<<"after read send"<<endl;
        nghttp2_session_send(d_session.get());
      }

      if (newState == IOState::Done) {
        if (isIdle()) {
          stopIO();
          watchForRemoteHostClosingConnection();
          ioGuard.release();
          break;
        }
      }
      else {
        if (newState == IOState::NeedWrite) {
           cerr<<"need write"<<endl;
          updateIO(IOState::NeedWrite, handleReadableIOCallback);
        }
        ioGuard.release();
        break;
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception while trying to read from HTTP backend connection: %s", e.what());
      handleIOError();
      break;
    }
  } while (getConcurrentStreamsCount() > 0);
}

void IncomingHTTP2Connection::handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  conn->handleIO();
}

void IncomingHTTP2Connection::handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  IOStateGuard ioGuard(conn->d_ioState);

  // cerr<<"in "<<__PRETTY_FUNCTION__<<" trying to write "<<conn->d_out.size()-conn->d_outPos<<endl;
  try {
    IOState newState = conn->d_handler.tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
    // cerr<<"got a "<<(int)newState<<" state, "<<conn->d_out.size()-conn->d_outPos<<" bytes remaining"<<endl;
    if (newState == IOState::NeedRead) {
      conn->updateIO(IOState::NeedRead, handleWritableIOCallback);
    }
    else if (newState == IOState::Done) {
      // cerr<<"done, buffer size was "<<conn->d_out.size()<<", pos was "<<conn->d_outPos<<endl;
      conn->d_out.clear();
      conn->d_outPos = 0;
      conn->stopIO();
      if (!conn->isIdle()) {
        conn->updateIO(IOState::NeedRead, handleReadableIOCallback);
      }
      else {
        conn->watchForRemoteHostClosingConnection();
      }
    }
    ioGuard.release();
  }
  catch (const std::exception& e) {
    vinfolog("Exception while trying to write (ready) to HTTP backend connection: %s", e.what());
    conn->handleIOError();
  }
}

bool IncomingHTTP2Connection::isIdle() const
{
  return getConcurrentStreamsCount() == 0;
}

void IncomingHTTP2Connection::stopIO()
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  d_ioState->reset();
}

uint32_t IncomingHTTP2Connection::getConcurrentStreamsCount() const
{
  return d_currentStreams.size();
}

void IncomingHTTP2Connection::updateIO(IOState newState, FDMultiplexer::callbackfunc_t callback, bool noTTD)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  #warning TODO timeouts
  boost::optional<struct timeval> ttd{boost::none};

  auto shared = std::dynamic_pointer_cast<IncomingHTTP2Connection>(shared_from_this());
  if (shared) {
    if (newState == IOState::NeedRead) {
      d_ioState->update(newState, callback, shared, ttd);
    }
    else if (newState == IOState::NeedWrite) {
      d_ioState->update(newState, callback, shared, ttd);
    }
  }
}

void IncomingHTTP2Connection::watchForRemoteHostClosingConnection()
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  updateIO(IOState::NeedRead, handleReadableIOCallback, false);
}

void IncomingHTTP2Connection::handleIOError()
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  d_connectionDied = true;
  nghttp2_session_terminate_session(d_session.get(), NGHTTP2_PROTOCOL_ERROR);
  d_currentStreams.clear();
  stopIO();
}
