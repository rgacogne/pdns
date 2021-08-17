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

#include <nghttp2/nghttp2.h>

#include "dnsdist-nghttp2.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"

#include "dolog.hh"
#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "tcpiohandler.hh"
#include "threadname.hh"
#include "sstuff.hh"

#warning remove me
#include "dnswriter.hh"

std::atomic<uint64_t> g_dohStatesDumpRequested{0};
std::unique_ptr<DoHClientCollection> g_dohClientThreads{nullptr};

class DoHConnectionToBackend: public TCPConnectionToBackend
{
public:
  DoHConnectionToBackend(std::shared_ptr<DownstreamState> ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now);

  void handleTimeout(const struct timeval& now, bool write) override
  {
#warning FIXME: we should notify the owners of pending queries / responses
  }

  void queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query) override;

  std::string toString() const override
  {
    ostringstream o;
    //o << "DoH connection to backend "<<(d_ds ? d_ds->getName() : "empty")<<" over FD "<<(d_handler ? std::to_string(d_handler->getDescriptor()) : "no socket")<<", state is "<<(int)d_state<<", io state is "<<(d_ioState ? std::to_string((int)d_ioState->getState()) : "empty")<<", queries count is "<<d_queries<<", pending queries count is "<<d_pendingQueries.size()<<", "<<d_pendingResponses.size()<<" pending responses";
    o << "DoH connection to backend "<<(d_ds ? d_ds->getName() : "empty")<<" over FD "<<(d_handler ? std::to_string(d_handler->getDescriptor()) : "no socket");
    return o.str();
  }

  bool canBeReused() const override;

private:
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data);
  static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data);
  static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);
  static int on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data);
  static void handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static void handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static void handleIO(std::shared_ptr<DoHConnectionToBackend>& conn, const struct timeval& now);

  class PendingRequest
  {
  public:
    std::shared_ptr<TCPQuerySender> d_sender{nullptr};
    TCPQuery d_query;
    PacketBuffer d_buffer;
    uint16_t d_responseCode{0};
    bool d_finished{false};
  };
  void addToIOState(IOState state, FDMultiplexer::callbackfunc_t callback);
  void updateIO(IOState newState, FDMultiplexer::callbackfunc_t callback);
  void stopIO();
  void handleResponse(PendingRequest&& request);
  void handleResponseError(PendingRequest&& request);
  uint32_t getConcurrentStreamsCount() const;

  //std::deque<TCPQuery> d_pendingQueries;
  static const std::unordered_map<std::string, std::string> s_constants;

  std::unique_ptr<nghttp2_session, void(*)(nghttp2_session*)> d_session{nullptr, nghttp2_session_del};
  std::unordered_map<int32_t, PendingRequest> d_currentStreams;
  PacketBuffer d_out;
  PacketBuffer d_in;
  size_t d_outPos{0};
  size_t d_inPos{0};
  uint32_t d_highestStreamID{0};
};

uint32_t DoHConnectionToBackend::getConcurrentStreamsCount() const
{
  return d_currentStreams.size();
}

void DoHConnectionToBackend::handleResponse(PendingRequest&& request)
{
  cerr<<"handle response!"<<endl;
  struct timeval now;
  gettimeofday(&now, nullptr);
  request.d_sender->handleResponse(now, TCPResponse(std::move(request.d_buffer), std::move(request.d_query.d_idstate), shared_from_this()));
}

void DoHConnectionToBackend::handleResponseError(PendingRequest&& request)
{
  cerr<<"handle response error!"<<endl;
  struct timeval now;
  gettimeofday(&now, nullptr);
  request.d_sender->notifyIOError(std::move(request.d_query.d_idstate), now);
}

bool DoHConnectionToBackend::canBeReused() const
{
  if (d_connectionDied) {
    return false;
  }
  const uint32_t maximumStreamID = (static_cast<uint32_t>(1) << 31) - 1;
  if (d_highestStreamID == maximumStreamID) {
    return false;
  }

  cerr<<"Got "<<getConcurrentStreamsCount()<<" concurrent streams, max is "<<nghttp2_session_get_remote_settings(d_session.get(), NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)<<endl;
  if (nghttp2_session_get_remote_settings(d_session.get(), NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) <= getConcurrentStreamsCount()) {
    return false;
  }

  return true;
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

const std::unordered_map<std::string, std::string> DoHConnectionToBackend::s_constants = {
  { "method-name", ":method" },
  { "method-value", "POST" },
};

void DoHConnectionToBackend::queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query)
{
  /* we could use nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_NAME and nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_VALUE
     to avoid a copy and lowercasing as long as we take care of making sure that the data will outlive the request
     and that it is already lowercased. */
  auto payloadSize = std::to_string(query.d_buffer.size());
  d_currentQuery = std::move(query);
  const nghttp2_nv hdrs[] = {
    { const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(s_constants.at("method-name").c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(s_constants.at("method-value").c_str())), s_constants.at("method-name").size(), s_constants.at("method-value").size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
      MAKE_NV2(":scheme", "https"),
      MAKE_NV(":authority", d_ds->d_tlsSubjectName.c_str(), d_ds->d_tlsSubjectName.size()),
      MAKE_NV(":path", d_ds->d_dohPath.c_str(), d_ds->d_dohPath.size()),
      MAKE_NV2("accept", "application/dns-message"),
      MAKE_NV2("content-type", "application/dns-message"),
      MAKE_NV("content-length", payloadSize.c_str(), payloadSize.size()),
      MAKE_NV2("user-agent", "nghttp2-" NGHTTP2_VERSION "/dnsdist")
  };

  /* if data_prd is not NULL, it provides data which will be sent in subsequent DATA frames. In this case, a method that allows request message bodies (https://tools.ietf.org/html/rfc7231#section-4) must be specified with :method key in nva (e.g. POST). This function does not take ownership of the data_prd. The function copies the members of the data_prd. If data_prd is NULL, HEADERS have END_STREAM set
   */

  nghttp2_data_provider data_provider;
  data_provider.source.ptr = this;
  data_provider.read_callback = [](nghttp2_session* session, int32_t stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data) -> ssize_t
  {
    auto userData = reinterpret_cast<DoHConnectionToBackend*>(user_data);
    if (userData->d_inPos >= userData->d_currentQuery.d_buffer.size()) {
       *data_flags |= NGHTTP2_DATA_FLAG_EOF;
       return 0;
    }
    size_t remaining = userData->d_currentQuery.d_buffer.size()- userData->d_inPos;
    size_t toCopy = length > remaining ? remaining : length;
    memcpy(buf, &userData->d_currentQuery.d_buffer.at(userData->d_inPos), toCopy);
    userData->d_inPos += toCopy;
    //cerr<<toCopy<<" written"<<endl;
    return toCopy;
  };

  auto stream_id = nghttp2_submit_request(d_session.get(), nullptr, hdrs, sizeof(hdrs)/sizeof(*hdrs), &data_provider, this);
  if (stream_id < 0) {
    d_connectionDied = true;
    throw std::runtime_error("Error submitting HTTP request:" + std::string(nghttp2_strerror(stream_id)));
  }
  //cerr<<"stream ID is "<<stream_id<<endl;

  auto rv = nghttp2_session_send(d_session.get());
  //cerr<<"nghttp2_session_send returned "<<rv<<endl;
  if (rv != 0) {
    d_connectionDied = true;
    throw std::runtime_error("Error in nghttp2_session_send:" + std::to_string(rv));
  }
  PendingRequest request;
  request.d_query = std::move(d_currentQuery);
  request.d_sender = std::move(sender);
  auto insertPair = d_currentStreams.insert({stream_id, std::move(request)});
  if (!insertPair.second) {
    /* there is a stream ID collision, something is very wrong! */
    d_connectionDied = true;
    nghttp2_session_terminate_session(d_session.get(), NGHTTP2_NO_ERROR);
    throw std::runtime_error("Stream ID collision");
  }

  d_highestStreamID = stream_id;
}

class DoHClientThreadData
{
public:
  DoHClientThreadData(): mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent()))
  {
  }

  std::unique_ptr<FDMultiplexer> mplexer{nullptr};
};

void DoHConnectionToBackend::handleIO(std::shared_ptr<DoHConnectionToBackend>& conn, const struct timeval& now)
{
}

void DoHConnectionToBackend::handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  //cerr<<"in "<<__PRETTY_FUNCTION__<<", param is "<<param.type().name()<<endl;
  auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }

  IOStateGuard ioGuard(conn->d_ioState);
  do {
    conn->d_inPos = 0;
    conn->d_in.resize(conn->d_in.size() + 512);
    //cerr<<"trying to read "<<conn->d_in.size()<<endl;
    try {
      IOState newState = conn->d_handler->tryRead(conn->d_in, conn->d_inPos, conn->d_in.size(), true);
      // userData.d_handler->tryRead(userData.d_in, pos, userData.d_in.size());
      //cerr<<"got a "<<(int)newState<<" state and "<<conn->d_inPos<<" bytes"<<endl;
      conn->d_in.resize(conn->d_inPos);
      if (newState == IOState::Done) {
        auto readlen = nghttp2_session_mem_recv(conn->d_session.get(), conn->d_in.data(), conn->d_inPos);
        //cerr<<"nghttp2_session_mem_recv returned "<<readlen<<endl;
        /* as long as we don't require a pause by returning nghttp2_error.NGHTTP2_ERR_PAUSE from a CB,
           all data should be consumed before returning */
        if (readlen > 0 && static_cast<size_t>(readlen) < conn->d_inPos) {
          cerr<<"Fatal error: "<<nghttp2_strerror((int)readlen)<<endl;
          return;
        }
        int rv = nghttp2_session_send(conn->d_session.get());
        //cerr<<"nghttp2_session_send returned "<<rv<<endl;
      }
      else {
        if (newState == IOState::NeedWrite) {
          conn->updateIO(IOState::NeedWrite, handleReadableIOCallback);
        }
        ioGuard.release();
        break;
      }
    }
    catch (const std::exception& e) {
      cerr<<"got exception "<<e.what()<<endl;
      break;
    }
  }
  while (true);

  //struct timeval now;
  //gettimeofday(&now, nullptr);
  //handleIO(conn, now);
}

void DoHConnectionToBackend::handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  cerr<<"in "<<__PRETTY_FUNCTION__<<", param is "<<param.type().name()<<endl;
  auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }
  IOStateGuard ioGuard(conn->d_ioState);

#warning TODO: once we have finished our handshake, check the ALPN/NPN that has been sent, with SSL_get0_next_proto_negotiated and/or SSL_get0_alpn_selected
  cerr<<"trying to write "<<conn->d_out.size()-conn->d_outPos<<endl;
  try {
    IOState newState = conn->d_handler->tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
    cerr<<"got a "<<(int)newState<<" state, "<<conn->d_out.size()-conn->d_inPos<<" bytes remaining"<<endl;
    if (newState == IOState::NeedRead) {
      conn->updateIO(IOState::NeedRead, handleWritableIOCallback);
    }
    else if (newState == IOState::Done) {
      conn->d_out.clear();
      conn->d_outPos = 0;
      conn->stopIO();
      conn->updateIO(IOState::NeedRead, handleReadableIOCallback);
    }
    ioGuard.release();
  }
  catch (const std::exception& e) {
    cerr<<"got exception "<<e.what()<<endl;
  }

  //struct timeval now;
  //gettimeofday(&now, nullptr);
  //handleIO(conn, now);
}

void DoHConnectionToBackend::stopIO()
{
  d_ioState->reset();
}

void DoHConnectionToBackend::updateIO(IOState newState, FDMultiplexer::callbackfunc_t callback)
{
  struct timeval now;
  gettimeofday(&now, nullptr);
  boost::optional<struct timeval> ttd{boost::none};
  if (newState == IOState::NeedRead) {
    ttd = getBackendReadTTD(now);
  }
  else if (isFresh() && d_queries == 0) {
    /* first write just after the non-blocking connect */
    ttd = getBackendConnectTTD(now);
  }
  else {
    ttd = getBackendWriteTTD(now);
  }

  auto shared = std::dynamic_pointer_cast<DoHConnectionToBackend>(shared_from_this());
  if (shared) {
    if (newState == IOState::NeedRead) {
      d_ioState->update(newState, callback, shared, ttd);
    }
    else if (newState == IOState::NeedWrite) {
      d_ioState->update(newState, callback, shared, ttd);
    }
  }
}

void DoHConnectionToBackend::addToIOState(IOState state, FDMultiplexer::callbackfunc_t callback)
{
  struct timeval now;
  gettimeofday(&now, nullptr);
  boost::optional<struct timeval> ttd{boost::none};
  if (state == IOState::NeedRead) {
    ttd = getBackendReadTTD(now);
  }
  else if (isFresh() && d_queries == 0) {
    /* first write just after the non-blocking connect */
    ttd = getBackendConnectTTD(now);
  }
  else {
    ttd = getBackendWriteTTD(now);
  }

  auto shared = std::dynamic_pointer_cast<DoHConnectionToBackend>(shared_from_this());
  if (shared) {
    if (state == IOState::NeedRead) {
      d_ioState->add(state, callback, shared, ttd);
    }
    else if (state == IOState::NeedWrite) {
      d_ioState->add(state, callback, shared, ttd);
    }
  }
}

ssize_t DoHConnectionToBackend::send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  cerr<<"asked to send "<<length<<" bytes"<<endl;
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  bool bufferWasEmpty = conn->d_out.empty();
  conn->d_out.insert(conn->d_out.end(), data, data + length);

  if (bufferWasEmpty) {
    auto state = conn->d_handler->tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
    if (state == IOState::Done) {
      conn->d_out.clear();
      conn->d_outPos = 0;
#warning FIXME from now on we need to read, as we might get an answer
      cerr<<"FIXME now we need to read!"<<endl;
      conn->addToIOState(IOState::NeedRead, handleReadableIOCallback);
    }
    else {
#warning write me should be addIO() instead, perhaps?
      cerr<<"now we need to wait for a writable (or readable) socket"<<endl;
      conn->updateIO(state, handleWritableIOCallback);
    }
  }

  return length;
}

int DoHConnectionToBackend::on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  cerr<<"Frame type is "<<std::to_string(frame->hd.type)<<endl;
  
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    cerr<<"got headers"<<endl;
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      cerr<<"All headers received"<<endl;
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

  /* is this the last frame for this stream? */
  if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
    if (stream != conn->d_currentStreams.end()) {
      cerr<<"Stream "<<frame->hd.stream_id<<" is now finished"<<endl;
      stream->second.d_finished = true;

      auto request = std::move(stream->second);
      conn->d_currentStreams.erase(stream->first);
      if (request.d_responseCode == 200U) {
        conn->handleResponse(std::move(request));
      } else {
        vinfolog("HTTP response has a non-200 status code: %d", request.d_responseCode);
        conn->handleResponseError(std::move(request));
      }
      if (conn->getConcurrentStreamsCount() == 0) {
        conn->stopIO();
      }
    }
    else {
      vinfolog("Stream %d NOT FOUND", frame->hd.stream_id);
      conn->d_connectionDied = true;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

int DoHConnectionToBackend::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data) {
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  cerr<<"Got data of size "<<len<<" for stream "<<stream_id<<endl;
  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    vinfolog("Unable to match the stream ID %d to a known one!", stream_id);
    conn->d_connectionDied = true;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (len > std::numeric_limits<uint16_t>::max() || (std::numeric_limits<uint16_t>::max() - stream->second.d_buffer.size()) < len) {
    vinfolog("Data frame of size %d is too large for a DNS response (we already have %d)", len, stream->second.d_buffer.size());
    conn->d_connectionDied = true;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  stream->second.d_buffer.insert(stream->second.d_buffer.end(), data, data + len);
  if (stream->second.d_finished) {
    cerr<<"we now have the full response!"<<endl;
    //cerr<<std::string(reinterpret_cast<const char*>(data), len)<<endl;

    auto request = std::move(stream->second);
    conn->d_currentStreams.erase(stream->first);
    if (request.d_responseCode == 200U) {
      conn->handleResponse(std::move(request));
    } else {
      vinfolog("HTTP response has a non-200 status code: %d", request.d_responseCode);
      conn->handleResponseError(std::move(request));
    }
    if (conn->getConcurrentStreamsCount() == 0) {
      conn->stopIO();
    }
  }
  else {
    cerr<<"but the stream is not finished yet"<<endl;
  }

  return 0;
}

int DoHConnectionToBackend::on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data) {
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);

  if (error_code != 0) {
    cerr<<"Stream "<<stream_id<<" closed with error_code="<<error_code<<endl;
    conn->d_connectionDied = true;
  }

  //auto rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
  //if (rv != 0) {
  //  return NGHTTP2_ERR_CALLBACK_FAILURE;
  //}

  return 0;
}

int DoHConnectionToBackend::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data) {
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);

  const std::string status(":status");
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      cerr<<"got header for "<<frame->hd.stream_id<<":"<<endl;
      cerr<<"- "<<std::string(reinterpret_cast<const char*>(name), namelen)<<endl;
      cerr<<"- "<<std::string(reinterpret_cast<const char*>(value), valuelen)<<endl;
      if (namelen == status.size() && memcmp(status.data(), name, status.size()) == 0) {
        auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
        if (stream == conn->d_currentStreams.end()) {
          vinfolog("Unable to match the stream ID %d to a known one!", frame->hd.stream_id);
          conn->d_connectionDied = true;
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        try {
          stream->second.d_responseCode = pdns_stou(std::string(reinterpret_cast<const char*>(value), valuelen));
        }
        catch (...) {
          vinfolog("Error parsing the status header for stream ID %d", frame->hd.stream_id);
          conn->d_connectionDied = true;
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }

      break;
    }
  }
  return 0;
}

int DoHConnectionToBackend::on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data) {
  vinfolog("Error in HTTP/2 connection: %s", std::string(msg, len));

  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  conn->d_connectionDied = true;

  return 0;
}

DoHConnectionToBackend::DoHConnectionToBackend(std::shared_ptr<DownstreamState> ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now): TCPConnectionToBackend(ds, mplexer, now)
{
  // inherit most of the stuff from the TCPConnectionToBackend()

  /* check ALPN:
SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (alpn == NULL) {
      SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      fprintf(stderr, "h2 is not negotiated\n");
      delete_http2_session_data(session_data);
      return;
    }
  */
  d_ioState = make_unique<IOStateHandler>(*d_mplexer, d_handler->getDescriptor());

  nghttp2_session_callbacks* cbs = nullptr;
  if (nghttp2_session_callbacks_new(&cbs) != 0) {
    d_connectionDied = true;
    vinfolog("Unable to create a callback object for a new HTTP/2 session");
    return;
  }
  std::unique_ptr<nghttp2_session_callbacks, void(*)(nghttp2_session_callbacks*)> callbacks(cbs, nghttp2_session_callbacks_del);
  cbs = nullptr;

  nghttp2_session_callbacks_set_send_callback(callbacks.get(), send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), on_stream_close_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), on_header_callback);
  nghttp2_session_callbacks_set_error_callback2(callbacks.get(), on_error_callback);

  nghttp2_session* sess = nullptr;
  if (nghttp2_session_client_new(&sess, callbacks.get(), this) != 0) {
    d_connectionDied = true;
    vinfolog("Coult not allocate a new HTTP/2 session");
    return;
  }

  d_session = std::unique_ptr<nghttp2_session, void(*)(nghttp2_session*)>(sess, nghttp2_session_del);
  sess = nullptr;

  callbacks.reset();

  nghttp2_settings_entry iv[] = {
    /* rfc7540 section-8.2.2:
       "Advertising a SETTINGS_MAX_CONCURRENT_STREAMS value of zero disables
       server push by preventing the server from creating the necessary
       streams."
    */
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 0},
    {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
    /* we might want to make the initial window size configurable, but 16M is a large enough default */
    {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 16*1024*1024}
  };
   /* client 24 bytes magic string will be sent by nghttp2 library */
  int rv = nghttp2_submit_settings(d_session.get(), NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(*iv));
  if (rv != 0) {
    d_connectionDied = true;
    vinfolog("Could not submit SETTINGS: %s", nghttp2_strerror(rv));
    return;
  }
}

class DownstreamDoHConnectionsManager
{
public:
  static std::shared_ptr<DoHConnectionToBackend> getConnectionToDownstream(std::unique_ptr<FDMultiplexer>& mplexer, std::shared_ptr<DownstreamState>& ds, const struct timeval& now);
  static void releaseDownstreamConnection(std::shared_ptr<DoHConnectionToBackend>&& conn);
  static void cleanupClosedConnections(struct timeval now);
  static size_t clear();

  static void setMaxCachedConnectionsPerDownstream(size_t max)
  {
    s_maxCachedConnectionsPerDownstream = max;
  }

  static void setCleanupInterval(uint16_t interval)
  {
    s_cleanupInterval = interval;
  }

private:
  static thread_local map<boost::uuids::uuid, std::deque<std::shared_ptr<DoHConnectionToBackend>>> t_downstreamConnections;
  static size_t s_maxCachedConnectionsPerDownstream;
  static time_t s_nextCleanup;
  static uint16_t s_cleanupInterval;
};

struct DoHClientCollection::DoHWorkerThread
{
  DoHWorkerThread()
  {
  }

  DoHWorkerThread(int crossProtocolPipe): d_crossProtocolQueryPipe(crossProtocolPipe)
  {
  }

  DoHWorkerThread(DoHWorkerThread&& rhs): d_crossProtocolQueryPipe(rhs.d_crossProtocolQueryPipe)
  {
    rhs.d_crossProtocolQueryPipe = -1;
  }

  DoHWorkerThread& operator=(DoHWorkerThread&& rhs)
  {
    if (d_crossProtocolQueryPipe != -1) {
      close(d_crossProtocolQueryPipe);
    }

    d_crossProtocolQueryPipe = rhs.d_crossProtocolQueryPipe;
    rhs.d_crossProtocolQueryPipe = -1;

    return *this;
  }

  DoHWorkerThread(const DoHWorkerThread& rhs) = delete;
  DoHWorkerThread& operator=(const DoHWorkerThread&) = delete;

  ~DoHWorkerThread()
  {
    if (d_crossProtocolQueryPipe != -1) {
      close(d_crossProtocolQueryPipe);
    }
  }

  int d_crossProtocolQueryPipe{-1};
};

DoHClientCollection::DoHClientCollection(size_t maxThreads): d_clientThreads(maxThreads), d_maxThreads(maxThreads)
{
}

bool DoHClientCollection::passCrossProtocolQueryToThread(std::unique_ptr<CrossProtocolQuery>&& cpq)
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

thread_local map<boost::uuids::uuid, std::deque<std::shared_ptr<DoHConnectionToBackend>>> DownstreamDoHConnectionsManager::t_downstreamConnections;
size_t DownstreamDoHConnectionsManager::s_maxCachedConnectionsPerDownstream{10};
time_t DownstreamDoHConnectionsManager::s_nextCleanup{0};
uint16_t DownstreamDoHConnectionsManager::s_cleanupInterval{60};

void DownstreamDoHConnectionsManager::cleanupClosedConnections(struct timeval now)
{
  struct timeval freshCutOff = now;
  freshCutOff.tv_sec -= 1;

  for (auto dsIt = t_downstreamConnections.begin(); dsIt != t_downstreamConnections.end(); ) {
    for (auto connIt = dsIt->second.begin(); connIt != dsIt->second.end(); ) {
      if (!(*connIt)) {
        ++connIt;
        continue;
      }

      /* don't bother checking freshly used connections */
      if (freshCutOff < (*connIt)->getLastDataReceivedTime()) {
        ++connIt;
        continue;
      }

      if (isTCPSocketUsable((*connIt)->getHandle())) {
        ++connIt;
      }
      else {
        connIt = dsIt->second.erase(connIt);
      }
    }

    if (!dsIt->second.empty()) {
      ++dsIt;
    }
    else {
      dsIt = t_downstreamConnections.erase(dsIt);
    }
  }
}

std::shared_ptr<DoHConnectionToBackend> DownstreamDoHConnectionsManager::getConnectionToDownstream(std::unique_ptr<FDMultiplexer>& mplexer, std::shared_ptr<DownstreamState>& ds, const struct timeval& now)
{
  std::shared_ptr<DoHConnectionToBackend> result;
  struct timeval freshCutOff = now;
  freshCutOff.tv_sec -= 1;

  auto backendId = ds->getID();

  if (s_cleanupInterval > 0 && (s_nextCleanup == 0 || s_nextCleanup <= now.tv_sec)) {
    s_nextCleanup = now.tv_sec + s_cleanupInterval;
    cleanupClosedConnections(now);
  }

  {
    const auto& it = t_downstreamConnections.find(backendId);
    if (it != t_downstreamConnections.end()) {
      auto& list = it->second;
      auto listIt = list.begin();
      while (listIt != list.end()) {
        auto& entry = *listIt;
        if (!entry->canBeReused()) {
          continue;
        }
        entry->setReused();
        /* for connections that have not been used very recently,
           check whether they have been closed in the meantime */
        if (freshCutOff < entry->getLastDataReceivedTime()) {
          /* used recently enough, skip the check */
          ++ds->tcpReusedConnections;
          return entry;
        }

        if (isTCPSocketUsable(entry->getHandle())) {
          ++ds->tcpReusedConnections;
          return entry;
        }

        /* otherwise let's try the next one, if any */
        ++listIt;
      }
    }

    auto newConnection = std::make_shared<DoHConnectionToBackend>(ds, mplexer, now);
    t_downstreamConnections[backendId].push_back(newConnection);
    return newConnection;
  }
}

static void handleCrossProtocolQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  auto threadData = boost::any_cast<DoHClientThreadData*>(param);
  CrossProtocolQuery* tmp{nullptr};

  ssize_t got = read(pipefd, &tmp, sizeof(tmp));
  if (got == 0) {
    throw std::runtime_error("EOF while reading from the DoH cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }
  else if (got == -1) {
    if (errno == EAGAIN || errno == EINTR) {
      return;
    }
    throw std::runtime_error("Error while reading from the DoH cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode:" + stringerror());
  }
  else if (got != sizeof(tmp)) {
    throw std::runtime_error("Partial read while reading from the DoH cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }

  try {
    struct timeval now;
    gettimeofday(&now, nullptr);

    std::shared_ptr<TCPQuerySender> tqs = tmp->getTCPQuerySender();
    auto query = std::move(tmp->query);
    auto downstreamServer = std::move(tmp->downstream);
    delete tmp;
    tmp = nullptr;

    auto downstream = DownstreamDoHConnectionsManager::getConnectionToDownstream(threadData->mplexer, downstreamServer, now);

#warning what about the proxy protocol payload, here, do we need to remove it? we likely need to handle forward-for headers?
    downstream->queueQuery(tqs, std::move(query));
  }
  catch (...) {
    delete tmp;
    tmp = nullptr;
    throw;
  }
}

static void dohClientThread(int crossProtocolPipeFD)
{
  setThreadName("dnsdist/dohClie");

  DoHClientThreadData data;

  data.mplexer->addReadFD(crossProtocolPipeFD, handleCrossProtocolQuery, &data);

  struct timeval now;
  gettimeofday(&now, nullptr);
  time_t lastTimeoutScan = now.tv_sec;

  for (;;) {
    data.mplexer->run(&now);

    if (now.tv_sec > lastTimeoutScan) {
      lastTimeoutScan = now.tv_sec;
      auto expiredReadConns = data.mplexer->getTimeouts(now, false);
      for (const auto& cbData : expiredReadConns) {
        if (cbData.second.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
          auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(cbData.second);
          vinfolog("Timeout (read) from remote DoH backend %s", conn->getBackendName());
          conn->handleTimeout(now, false);
        }
      }

      auto expiredWriteConns = data.mplexer->getTimeouts(now, true);
      for (const auto& cbData : expiredWriteConns) {
        if (cbData.second.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
          auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(cbData.second);
          vinfolog("Timeout (write) from remote DoH backend %s", conn->getBackendName());
          conn->handleTimeout(now, true);
        }
      }

      if (g_dohStatesDumpRequested > 0) {
        /* just to keep things clean in the output, debug only */
        static std::mutex s_lock;
        std::lock_guard<decltype(s_lock)> lck(s_lock);
        if (g_dohStatesDumpRequested > 0) {
          /* no race here, we took the lock so it can only be increased in the meantime */
          --g_dohStatesDumpRequested;
          errlog("Dumping the DoH client states, as requested:");
          data.mplexer->runForAllWatchedFDs([](bool isRead, int fd, const FDMultiplexer::funcparam_t& param, struct timeval ttd)
          {
            struct timeval lnow;
            gettimeofday(&lnow, nullptr);
            if (ttd.tv_sec > 0) {
            errlog("- Descriptor %d is in %s state, TTD in %d", fd, (isRead ? "read" : "write"), (ttd.tv_sec-lnow.tv_sec));
            }
            else {
              errlog("- Descriptor %d is in %s state, no TTD set", fd, (isRead ? "read" : "write"));
            }

            if (param.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
              auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
              errlog(" - %s", conn->toString());
            }
            else if (param.type() == typeid(DoHClientThreadData*)) {
              errlog(" - Worker thread pipe");
            }
          });
        }
      }
    }
  }
}

void DoHClientCollection::addThread()
{
  auto preparePipe = [](int fds[2], const std::string& type) -> bool {
    if (pipe(fds) < 0) {
      errlog("Error creating the DoH thread %s pipe: %s", type, stringerror());
      return false;
    }

    if (!setNonBlocking(fds[0])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      errlog("Error setting the DoH thread %s pipe non-blocking: %s", type, stringerror(err));
      return false;
    }

    if (!setNonBlocking(fds[1])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      errlog("Error setting the DoH thread %s pipe non-blocking: %s", type, stringerror(err));
      return false;
    }

    if (g_tcpInternalPipeBufferSize > 0 && getPipeBufferSize(fds[0]) < g_tcpInternalPipeBufferSize) {
      setPipeBufferSize(fds[0], g_tcpInternalPipeBufferSize);
    }

    return true;
  };

  int crossProtocolFDs[2] = { -1, -1};
  if (!preparePipe(crossProtocolFDs, "cross-protocol")) {
    return;
  }

  vinfolog("Adding DoH Client thread");

  {
    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_numberOfThreads >= d_clientThreads.size()) {
      vinfolog("Adding a new DoH client thread would exceed the vector size (%d/%d), skipping. Consider increasing the maximum amount of DoH client threads with setMaxDoHClientThreads() in the configuration.", d_numberOfThreads.load(), d_clientThreads.size());
      close(crossProtocolFDs[0]);
      close(crossProtocolFDs[1]);
      return;
    }

    /* from now on this side of the pipe will be managed by that object,
       no need to worry about it */
    DoHWorkerThread worker(crossProtocolFDs[1]);
    try {
      std::thread t1(dohClientThread, crossProtocolFDs[0]);
      t1.detach();
    }
    catch (const std::runtime_error& e) {
      /* the thread creation failed, don't leak */
      errlog("Error creating a DoH thread: %s", e.what());
      close(crossProtocolFDs[0]);
      return;
    }

    d_clientThreads.at(d_numberOfThreads) = std::move(worker);
    ++d_numberOfThreads;
  }
}

bool initDoHWorkers()
{
#warning FIXME: number of DoH threads
  g_dohClientThreads = std::make_unique<DoHClientCollection>(1);
  g_dohClientThreads->addThread();
  return true;
}

static bool select_next_proto_callback(unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    vinfolog("The remote DoH backend did not advertise " NGHTTP2_PROTO_VERSION_ID);
    return false;
  }
  return true;
}

bool setupDoHClientProtocolNegotiation(std::shared_ptr<TLSCtx>& ctx)
{
  if (ctx == nullptr) {
    return false;
  }
  const std::vector<std::vector<uint8_t>> h2Alpns = {{'h', '2'}};
  ctx->setALPNProtos(h2Alpns);
  ctx->setNextProtocolSelectCallback(select_next_proto_callback);
  return true;
}
