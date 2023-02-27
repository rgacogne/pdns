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

class IncomingDoHEndpoint
{
  TLSFrontend
};

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

  std::optional<std::unordered_map<std::string, std::string>> getHTTPHeaders() const override
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

IncomingHTTP2Connection::IncomingHTTP2Connection(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): d_threadData(threadData), d_handler(ci.fd, timeval{g_tcpRecvTimeout,0}, ci.cs->tlsFrontend->getContext(), now.tv_sec)
  {
    ci.fd = -1;
    d_ioState = make_unique<IOStateHandler>(*d_threadData.mplexer, d_handler.getDescriptor());

    nghttp2_session_callbacks* cbs = nullptr;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
      throw std::runtime_error("Unable to create a callback object for a new incoming HTTP/2 session");
    }
    std::unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks*)> callbacks(cbs, nghttp2_session_callbacks_del);
    cbs = nullptr;

    nghttp2_session_callbacks_set_send_callback(callbacks.get(), send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), on_frame_recv_callback);
//    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), on_stream_close_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks.get(), on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), on_header_callback);
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
#warning tODO
#if 0
  SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (alpn == NULL) {
    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
  }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
    fprintf(stderr, "%s h2 is not negotiated\n", session_data->client_addr);
    delete_http2_session_data(session_data);
    return;
  }
#endif
  return true;
}

void IncomingHTTP2Connection::handleIO()
{
  IOState iostate = IOState::Done;

  try {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  if (d_state == State::doingHandshake) {
    cerr<<"try handshake"<<endl;
    iostate = d_handler.tryHandshake();
    if (iostate == IOState::Done) {
      cerr<<"handshake done"<<endl;
#warning handle proxy protocol
      d_state = State::running;
      if (d_handler.isTLS()) {
        cerr<<"is TLS"<<endl;
        if (!checkALPN()) {
          cerr<<"ALPN failed"<<endl;
        }
      }
      const std::array<nghttp2_settings_entry, 1> iv{
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
    else {
      cerr<<"not done"<<endl;
    }
  }
  else {
    readHTTPData();
  }

//  if (iostate == IOState::Done && d_state == State::running) {
    if (nghttp2_session_want_read(d_session.get())) {
      cerr<<"wants read"<<endl;
      d_ioState->add(IOState::NeedRead, &handleReadableIOCallback, shared_from_this(), boost::none);
    }
    if (nghttp2_session_want_write(d_session.get())) {
      cerr<<"wants write"<<endl;
      d_ioState->add(IOState::NeedWrite, &handleWritableIOCallback, shared_from_this(), boost::none);
    }
//  }
  }
  catch (const std::exception& e)
  {
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
  else {
    cerr<<"was not empty"<<endl;
  }

  return length;
}

static const std::unordered_map<std::string, std::string> s_constants = {
  {"200-value", "200"},
  {"method-name", ":method"},
  {"method-value", "POST"},
  {"scheme-name", ":scheme"},
  {"scheme-value", "https"},
  {"accept-name", "accept"},
  {"accept-value", "application/dns-message"},
  {"content-type-name", "content-type"},
  {"content-type-value", "application/dns-message"},
  {"user-agent-name", "user-agent"},
  {"user-agent-value", "nghttp2-" NGHTTP2_VERSION "/dnsdist"},
  {"authority-name", ":authority"},
  {"path-name", ":path"},
  {"content-length-name", "content-length"},
  {"status-name", ":status"},
  {"x-forwarded-for-name", "x-forwarded-for"},
  {"x-forwarded-port-name", "x-forwarded-port"},
  {"x-forwarded-proto-name", "x-forwarded-proto"},
  {"x-forwarded-proto-value-dns-over-udp", "dns-over-udp"},
  {"x-forwarded-proto-value-dns-over-tcp", "dns-over-tcp"},
  {"x-forwarded-proto-value-dns-over-tls", "dns-over-tls"},
  {"x-forwarded-proto-value-dns-over-http", "dns-over-http"},
  {"x-forwarded-proto-value-dns-over-https", "dns-over-https"},
};

static void addStaticHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& valueKey)
{
  const auto& name = s_constants.at(nameKey);
  const auto& value = s_constants.at(valueKey);

  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

static void addDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& value)
{
  const auto& name = s_constants.at(nameKey);

  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

bool IncomingHTTP2Connection::sendResponse(IncomingHTTP2Connection::StreamID streamID, uint8_t responseCode, const PacketBuffer& responseBody)
{
  /* if data_prd is not NULL, it provides data which will be sent in subsequent DATA frames. In this case, a method that allows request message bodies (https://tools.ietf.org/html/rfc7231#section-4) must be specified with :method key (e.g. POST). This function does not take ownership of the data_prd. The function copies the members of the data_prd. If data_prd is NULL, HEADERS have END_STREAM set.
   */
  nghttp2_data_provider data_provider;

  data_provider.source.ptr = this;
  data_provider.read_callback = [](nghttp2_session*, IncomingHTTP2Connection::StreamID stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* cb_data) -> ssize_t {
    auto connection = reinterpret_cast<IncomingHTTP2Connection*>(cb_data);
    auto& obj = connection->d_currentStreams.at(stream_id);
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

  cerr<<"adding headers"<<endl;
  const std::string contentLength = std::to_string(responseBody.size());
  std::vector<nghttp2_nv> headers;
  if (responseCode == 200) {
    addStaticHeader(headers, "status-name", "200-value");
  }
  else {
    std::string responseCodeStr = std::to_string(responseCode);
    addDynamicHeader(headers, "status-name", responseCodeStr);
  }
  addDynamicHeader(headers, "content-length-name", contentLength);

  cerr<<"submitting response"<<endl;
  auto ret = nghttp2_submit_response(d_session.get(), streamID, headers.data(), headers.size(), &data_provider);
  if (ret != 0) {
    d_currentStreams.erase(streamID);
    vinfolog("Error submitting HTTP response for stream %d: %s", streamID, nghttp2_strerror(ret));
    return false;
  }

  ret = nghttp2_session_send(d_session.get());
  if (ret != 0) {
    d_currentStreams.erase(streamID);
    vinfolog("Error flushing HTTP response for stream %d: %s", streamID, nghttp2_strerror(ret));
    return false;
  }

  return true;
}


void IncomingHTTP2Connection::handleIncomingQuery(IncomingHTTP2Connection::PendingQuery&& query, IncomingHTTP2Connection::StreamID streamID)
{
  const auto handleImmediateResponse = [&query, streamID](uint8_t code, const char* reason, PacketBuffer&& response = PacketBuffer()) {
#warning writeme
  };

  try {
    //DOHServerConfig* dsc = du->dsc;
    //auto& holders = dsc->holders;
    //ClientState& cs = *dsc->cs;
    InternalQueryState ids;
    uint16_t queryId;

    if (query.d_buffer.size() < sizeof(dnsheader)) {
      ++g_stats.nonCompliantQueries;
      ++cs.nonCompliantQueries;
      handleImmediateResponse(400, "DoH non-compliant query");
      return;
    }

    ++cs.queries;
    ++g_stats.queries;
    ids.queryRealTime.start();

    {
      /* don't keep that pointer around, it will be invalidated if the buffer is ever resized */
      struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query.d_buffer.data());
      
      if (!checkQueryHeaders(dh, cs)) {
        handleImmediateResponse(400, "DoH invalid headers");
      return;
    }

    if (dh->qdcount == 0) {
      dh->rcode = RCode::NotImp;
      dh->qr = true;
      handleImmediateResponse(200, "DoH empty query", std::move(query.d_buffer));
      return;
    }
    
    queryId = ntohs(dh->id);
    }

    ids.qname = DNSName(reinterpret_cast<const char*>(query.d_buffer.data()), query.d_buffer.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
    DNSQuestion dq(ids, query.d_buffer);
    const uint16_t* flags = getFlagsFromDNSHeader(dq.getHeader());
    ids.origFlags = *flags;
    ids.cs = &cs;
    dq.sni = std::move(du->sni);

    {
      // if there was no EDNS, we add it with a large buffer size
      // so we can use UDP to talk to the backend.
      auto dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(query.d_buffer.data()));

      if (!dh->arcount) {
        if (generateOptRR(std::string(), query.d_buffer, 4096, 4096, 0, false)) {
          dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(query.d_buffer.data())); // may have reallocated
          dh->arcount = htons(1);
          ids.ednsAdded = true;
        }
      }
      else {
        // we leave existing EDNS in place
      }
    }

    std::shared_ptr<DownstreamState> downstream;
    auto result = processQuery(dq, holders, downstream);

    if (result == ProcessQueryResult::Drop) {
      handleImmediateResponse(403, "DoH dropped query");
      return;
    }
    else if (result == ProcessQueryResult::Asynchronous) {
      return;
    }
    else if (result == ProcessQueryResult::SendAnswer) {
      if (response.empty()) {
        response = std::move(query.d_buffer);
      }
      if (response.size() >= sizeof(dnsheader) && contentType.empty()) {
        auto dh = reinterpret_cast<const struct dnsheader*>(response.data());

        handleResponseSent(ids.qname, QType(ids.qtype), 0., ids.origDest, ComboAddress(), response.size(), *dh, dnsdist::Protocol::DoH, dnsdist::Protocol::DoH);
      }
      handleImmediateResponse(200, "DoH self-answered response", response);
      return;
    }

    if (result != ProcessQueryResult::PassToBackend) {
      handleImmediateResponse(500, "DoH no backend available");
      return;
    }

    if (downstream == nullptr) {
      handleImmediateResponse(502, "DoH no backend available");
      return;
    }

    if (downstream->isTCPOnly()) {
      std::string proxyProtocolPayload;
      /* we need to do this _before_ creating the cross protocol query because
         after that the buffer will have been moved */
      if (downstream->d_config.useProxyProtocol) {
        proxyProtocolPayload = getProxyProtocolPayload(dq);
      }

      ids.origID = htons(queryId);
      du->tcp = true;

      /* this moves ids, careful! */
      auto cpq = std::make_unique<DoHCrossProtocolQuery>(std::move(du), false);
      cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

      if (downstream->passCrossProtocolQuery(std::move(cpq))) {
        return;
      }
      else {
        handleImmediateResponse(502, "DoH internal error");
        return;
      }
    }

    ComboAddress dest = dq.ids.origDest;
    ids.crossProtocolContext = std::make_unique<IncomingDoHCrossProtocolContext>(std::move(query), shared_from_this(), streamID);
    if (!assignOutgoingUDPQueryToBackend(downstream, htons(queryId), dq, query.d_buffer, dest)) {
      handleImmediateResponse(502, "DoH internal error");
      return;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in DOH question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
    handleImmediateResponse(500, "DoH internal error");
    return;
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
    #warning TODO
  }

  /* is this the last frame for this stream? */
  else if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    auto streamID = frame->hd.stream_id;
    auto stream = conn->d_currentStreams.find(streamID);
    if (stream != conn->d_currentStreams.end()) {
      stream->second.d_finished = true;
      cerr<<"got query of size "<<stream->second.d_buffer.size()<<endl;

      conn->handleIncomingQuery(std::move(stream->second), streamID);

//      conn->sendResponse(streamID, 200, stream->second.d_buffer);

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
  if (stream->second.d_finished) {
     cerr<<"we now have the full response!"<<endl;
    // cerr<<std::string(reinterpret_cast<const char*>(data), len)<<endl;

    auto request = std::move(stream->second);
    conn->d_currentStreams.erase(stream->first);
    cerr<<"got query"<<endl;

    if (conn->isIdle()) {
      conn->stopIO();
      conn->watchForRemoteHostClosingConnection();
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
  cerr<<"inserted pending query for "<<frame->hd.stream_id<<endl;
  if (!insertPair.second) {
    /* there is a stream ID collision, something is very wrong! */
    //d_connectionDied = true;
    nghttp2_session_terminate_session(conn->d_session.get(), NGHTTP2_NO_ERROR);
    throw std::runtime_error("Stream ID collision");
  }
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

int IncomingHTTP2Connection::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  const std::string path(":path");
  const std::string method(":method");
  if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    if (nghttp2_check_header_name(name, namelen) == 0) {
      vinfolog("Invalid header name");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (nghttp2_check_header_value_rfc9113(value, valuelen) == 0) {
      vinfolog("Invalid header value");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    cerr<<"id is "<<frame->hd.stream_id<<endl;
    auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
    if (stream == conn->d_currentStreams.end()) {
      vinfolog("Unable to match the stream ID %d to a known one!", frame->hd.stream_id);
      cerr<<"NOT found"<<endl;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto valueView = std::string_view(reinterpret_cast<const char*>(value), valuelen);
    // cerr<<"got header for "<<frame->hd.stream_id<<":"<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(name), namelen)<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(value), valuelen)<<endl;
    if (namelen == path.size() && memcmp(path.data(), name, path.size()) == 0) {
      if (nghttp2_check_path(value, valuelen) == 0) {
        vinfolog("Invalid path value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      stream->second.d_path = std::string(valueView);
      cerr<<"Got path: "<<stream->second.d_path<<endl;
    }
    else if (namelen == method.size() && memcmp(method.data(), name, method.size()) == 0) {
      cerr<<"Got method: "<<valueView<<endl;
      if (nghttp2_check_method(value, valuelen) == 0) {
        vinfolog("Invalid method value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      if (valueView == "GET") {
        stream->second.d_method = PendingQuery::Method::Get;
      }
      else if (valueView == "POST") {
        stream->second.d_method = PendingQuery::Method::Post;
      }
      else {
        vinfolog("Unsupported method value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }

    if (stream->second.d_buffer.empty() && stream->second.d_method == PendingQuery::Method::Get && !stream->second.d_path.empty()) {
      auto payload = getPayloadFromPath(valueView);
      if (payload) {
        cerr<<"Got payload of size "<<payload->size()<<endl;
        stream->second.d_buffer = std::move(*payload);
        cerr<<"buffer size is now "<<stream->second.d_buffer.size();
      }
      else {
        cerr<<"unable to get payload"<<endl;
      }
    }

    #warning store headers if needed
    #warning handle x-forwarded-for and the likes
  }
  return 0;
}

int IncomingHTTP2Connection::on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data)
{
  cerr<<__PRETTY_FUNCTION__<<endl;
  vinfolog("Error in HTTP/2 connection: %s", std::string(msg, len));

  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  #warning TODO
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
        if (readlen > 0 && static_cast<size_t>(readlen) < d_inPos) {
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
  cerr<<__PRETTY_FUNCTION__<<endl;
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
  #warning TODO
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
  //d_connectionDied = true;
  nghttp2_session_terminate_session(d_session.get(), NGHTTP2_PROTOCOL_ERROR);
  d_currentStreams.clear();
  stopIO();
}
