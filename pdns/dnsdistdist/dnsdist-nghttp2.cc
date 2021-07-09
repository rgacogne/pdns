
#include <nghttp2/nghttp2.h>

#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "tcpiohandler.hh"
#include "sstuff.hh"

struct MyUserData
{
  nghttp2_session* session{nullptr};
  std::unique_ptr<TCPIOHandler> handler;
  PacketBuffer out;
  PacketBuffer in;
  size_t outPos{0};
};

static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  MyUserData* userData = reinterpret_cast<MyUserData*>(user_data);
  userData->out.insert(userData->out.end(), data, data + length);
  userData->handler->write(userData->out.data() + userData->outPos, userData->out.size() - userData->outPos, timeval{2, 0});
  userData->out.clear();
  return length;
}

static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  MyUserData* userData = reinterpret_cast<MyUserData*>(user_data);
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      cerr<<"All headers received"<<endl;
    }
    break;
  }
  return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  MyUserData* userData = reinterpret_cast<MyUserData*>(user_data);
  cerr<<"Got data of size "<<len<<endl;
  cerr<<std::string(reinterpret_cast<const char*>(data), len)<<endl;
  return 0;
}

static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  MyUserData* userData = reinterpret_cast<MyUserData*>(user_data);

  cerr<<"Stream "<<stream_id<<" closed with error_code="<<error_code<<endl;
  auto rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
  if (rv != 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  MyUserData* userData = reinterpret_cast<MyUserData*>(user_data);

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      /* Print response headers for the initiated request. */
      cerr<<"got header for "<<frame->hd.stream_id<<":"<<endl;
      cerr<<"- "<<std::string(reinterpret_cast<const char*>(name), namelen)<<endl;
      cerr<<"- "<<std::string(reinterpret_cast<const char*>(value), valuelen)<<endl;
      break;
    }
  }
  return 0;
}

static int on_begin_headers_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
  cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  MyUserData* userData = reinterpret_cast<MyUserData*>(user_data);

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      cerr<<"Response headers for stream ID="<<frame->hd.stream_id<<endl;
    }
    break;
  }
  return 0;
}

static void doReadData(MyUserData& userData)
{
  do {
    size_t pos = 0;
    userData.in.resize(512);
    cerr<<"trying to read "<<userData.in.size()<<endl;
    try {
      userData.handler->read(userData.in.data(), userData.in.size(), timeval{10, 0});
      // userData.handler->tryRead(userData.in, pos, userData.in.size());
      cerr<<"got "<<pos<<endl;
      userData.in.resize(pos);
      if (pos > 0) {
        auto readlen = nghttp2_session_mem_recv(userData.session, userData.in.data(), pos);
        cerr<<"nghttp2_session_mem_recv returned "<<readlen<<endl;
        if (readlen < 0) {
          cerr<<"Fatal error: "<<nghttp2_strerror((int)readlen)<<endl;
          return;
        }
        int rv = nghttp2_session_send(userData.session);
        cerr<<"nghttp2_session_send returned "<<rv<<endl;
      }
      else {
        break;
      }
    }
    catch (const std::exception& e) {
      cerr<<"got exception "<<e.what()<<endl;
      break;
    }
  }
  while (true);
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
void sendHTTP2Query()
{
  auto remote = ComboAddress("9.9.9.11:443");
  std::string host("dns11.quad9.net");
  std::string path("/dns-query");
  struct TLSContextParameters tlsParams;
  tlsParams.d_provider = "openssl";
  std::shared_ptr<TLSCtx> tlsCtx = getTLSContext(tlsParams);

  Socket sock(remote.sin4.sin_family, SOCK_STREAM);
  // FIXME
  auto fd = sock.getHandle();
  setTCPNoDelay(fd);
  MyUserData userData;
  userData.handler = std::make_unique<TCPIOHandler>(host, sock.releaseHandle(), timeval{2, 0}, tlsCtx, time(nullptr));
  userData.handler->connect(true, remote, timeval{2, 0});

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

  #warning FIXME smart ptr
  nghttp2_session_callbacks* callbacks = nullptr;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
                                                            on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                         on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                          on_begin_headers_callback);

#warning check return value
  nghttp2_session_client_new(&userData.session, callbacks, &userData);

  nghttp2_session_callbacks_del(callbacks);
  callbacks = nullptr;

  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
   /* client 24 bytes magic string will be sent by nghttp2 library */
  int rv = nghttp2_submit_settings(userData.session, NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(*iv));
  if (rv != 0) {
    cerr<<"Could not submit SETTINGS: "<<nghttp2_strerror(rv)<<endl;
    return;
  }

  /* we could use nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_NAME and nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_VALUE
     to avoid a copy and lowercasing as long as we take care of making sure that the data will outlive the request
     and that it is already lowercased. */
  const nghttp2_nv hdrs[] = {
      MAKE_NV2(":method", "GET"),
      MAKE_NV2(":scheme", "https"),
      MAKE_NV(":authority", host.c_str(), host.size()),
      MAKE_NV(":path", path.c_str(), path.size())
  };

  /* f data_prd is not NULL, it provides data which will be sent in subsequent DATA frames. In this case, a method that allows request message bodies (https://tools.ietf.org/html/rfc7231#section-4) must be specified with :method key in nva (e.g. POST). This function does not take ownership of the data_prd. The function copies the members of the data_prd. If data_prd is NULL, HEADERS have END_STREAM set
   */
  auto stream_id = nghttp2_submit_request(userData.session, nullptr, hdrs, sizeof(hdrs)/sizeof(*hdrs), nullptr, &userData);
  if (stream_id < 0) {
    cerr<<"Could not submit HTTP request: "<<nghttp2_strerror(stream_id)<<endl;
    return;
  }
  rv = nghttp2_session_send(userData.session);
  
  setNonBlocking(fd);

  doReadData(userData);
}

