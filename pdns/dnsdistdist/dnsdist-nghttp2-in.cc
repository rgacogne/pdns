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

#include "dnsdist-nghttp2-in.hh"

IncomingHTTP2Connection::IncomingHTTP2Connection(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): d_threadData(threadData), d_handler(ci.fd, timeval{g_tcpRecvTimeout,0}, ci.cs->tlsFrontend->getContext(), now.tv_sec)
  {
    ci.fd = -1;
    d_ioState = make_unique<IOStateHandler>(d_threadData.mplexer, d_handler.getDescriptor());

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

    if (d_state == State::doingHandshake) {
      iostate = d_handler.tryHandshake();
      if (iostate == IOState::Done) {
        DEBUGLOG("handshake done");
#warning handle proxy protocol
        d_state = State::running;
        if (d_handler.isTLS()) {
          if (!checkALPN()) {
            cerr<<"ALPN failed"<<endl;
          }
        }
        std::array<nghttp2_settings_entry, 1> iv{
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
    }

    if (iostate == IOState::Done && d_state == State::running) {
      if (nghttp2_session_want_read(d_session.get())) {
        d_ioState->add(IOState::NeedRead, handleReadableCallback, shared_from_this(), std::nullopt);
      }
      if (nghttp2_session_want_write(d_session.get())) {
        d_ioState->add(IOState::NeedWrite, handleWritableCallback, shared_from_this(), std::nullopt);
      }
    }
  }

ssize_t IncomingHTTP2Connection::send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  bool bufferWasEmpty = conn->d_out.empty();
  conn->d_out.insert(conn->d_out.end(), data, data + length);

  if (bufferWasEmpty) {
    try {
      auto state = conn->d_handler->tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
      if (state == IOState::Done) {
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

int IncomingHTTP2Connection::on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  if (frame->hd.type == NGHTTP2_GOAWAY) {
    conn->d_connectionDied = true;
  }

  /* is this the last frame for this stream? */
  else if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
    if (stream != conn->d_currentStreams.end()) {
      stream->second.d_finished = true;

      cerr<<"got query"<<endl;

      if (conn->isIdle()) {
        conn->stopIO();
        conn->watchForRemoteHostClosingConnection();
      }
    }
    else {
      vinfolog("Stream %d NOT FOUND", frame->hd.stream_id);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

int IncomingHTTP2Connection::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  // cerr<<"Got data of size "<<len<<" for stream "<<stream_id<<endl;
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
    // cerr<<"we now have the full response!"<<endl;
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

int IncomingHTTP2Connection::on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
{
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

int IncomingHTTP2Connection::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  const std::string path(":path");
  if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    // cerr<<"got header for "<<frame->hd.stream_id<<":"<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(name), namelen)<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(value), valuelen)<<endl;
    if (namelen == path.size() && memcmp(path.data(), name, path.size()) == 0) {
      cerr<<"Got path"<<endl;
      auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
      if (stream == conn->d_currentStreams.end()) {
        vinfolog("Unable to match the stream ID %d to a known one!", frame->hd.stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
  }
  return 0;
}

int IncomingHTTP2Connection::on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data)
{
  vinfolog("Error in HTTP/2 connection: %s", std::string(msg, len));

  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  conn->d_connectionDied = true;
  ++conn->d_ds->tcpDiedReadingResponse;

  return 0;
}

void IncomingHTTP2Connection::handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }

  IOStateGuard ioGuard(conn->d_ioState);
  do {
    conn->d_inPos = 0;
    conn->d_in.resize(conn->d_in.size() + 512);
    // cerr<<"trying to read "<<conn->d_in.size()<<endl;
    try {
      IOState newState = conn->d_handler.tryRead(conn->d_in, conn->d_inPos, conn->d_in.size(), true);
      // cerr<<"got a "<<(int)newState<<" state and "<<conn->d_inPos<<" bytes"<<endl;
      conn->d_in.resize(conn->d_inPos);

      if (conn->d_inPos > 0) {
        /* we got something */
        auto readlen = nghttp2_session_mem_recv(conn->d_session.get(), conn->d_in.data(), conn->d_inPos);
        // cerr<<"nghttp2_session_mem_recv returned "<<readlen<<endl;
        /* as long as we don't require a pause by returning nghttp2_error.NGHTTP2_ERR_PAUSE from a CB,
           all data should be consumed before returning */
        if (readlen > 0 && static_cast<size_t>(readlen) < conn->d_inPos) {
          throw std::runtime_error("Fatal error while passing received data to nghttp2: " + std::string(nghttp2_strerror((int)readlen)));
        }

        struct timeval now;
        gettimeofday(&now, nullptr);
        conn->d_lastDataReceivedTime = now;

        // cerr<<"after read send"<<endl;
        nghttp2_session_send(conn->d_session.get());
      }

      if (newState == IOState::Done) {
        if (conn->isIdle()) {
          conn->stopIO();
          conn->watchForRemoteHostClosingConnection();
          ioGuard.release();
          break;
        }
      }
      else {
        if (newState == IOState::NeedWrite) {
          // cerr<<"need write"<<endl;
          conn->updateIO(IOState::NeedWrite, handleReadableIOCallback);
        }
        ioGuard.release();
        break;
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception while trying to read from HTTP backend connection: %s", e.what());
      ++conn->d_ds->tcpDiedReadingResponse;
      conn->handleIOError();
      break;
    }
  } while (conn->getConcurrentStreamsCount() > 0);
}

void IncomingHTTP2Connection::handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }
  IOStateGuard ioGuard(conn->d_ioState);

  // cerr<<"in "<<__PRETTY_FUNCTION__<<" trying to write "<<conn->d_out.size()-conn->d_outPos<<endl;
  try {
    IOState newState = conn->d_handler->tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
    // cerr<<"got a "<<(int)newState<<" state, "<<conn->d_out.size()-conn->d_outPos<<" bytes remaining"<<endl;
    if (newState == IOState::NeedRead) {
      conn->updateIO(IOState::NeedRead, handleWritableIOCallback);
    }
    else if (newState == IOState::Done) {
      // cerr<<"done, buffer size was "<<conn->d_out.size()<<", pos was "<<conn->d_outPos<<endl;
      conn->d_firstWrite = false;
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
    ++conn->d_ds->tcpDiedSendingQuery;
    conn->handleIOError();
  }
}
