
#pragma once
#include <memory>

#include "misc.hh"

class TLSConnection
{
public:
  virtual ~TLSConnection() { }
  virtual size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout) = 0;
  virtual size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) = 0;
  virtual void close() = 0;
protected:
  int d_socket{-1};
};

class TLSCtx;

class TLSFrontend
{
public:
  bool setupTLS();
  void cleanup()
  {
    d_ctx = nullptr;
  }

  std::set<int> d_cpus;
  ComboAddress d_addr;
  std::string d_certFile;
  std::string d_keyFile;
  std::string d_caFile;
  std::string d_ciphers;
  std::string d_provider;
  std::string d_interface;
  std::shared_ptr<TLSCtx> d_ctx{nullptr};

  time_t d_ticketsKeyRotationDelay{43200};
  int d_tcpFastOpenQueueSize{0};
  bool d_reusePort{false};
};

class TLSCtx
{
public:
  virtual ~TLSCtx() {}
  virtual std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout, time_t now) = 0;
  virtual void rotateTicketsKey(time_t now) = 0;
};

class TCPIOHandler
{
public:
  TCPIOHandler(int socket, unsigned int timeout, std::shared_ptr<TLSCtx> ctx, time_t now): d_socket(socket)
  {
    if (ctx) {
      d_conn = ctx->getConnection(d_socket, timeout, now);
    }
  }
  ~TCPIOHandler()
  {
    if (d_conn) {
      d_conn->close();
    }
    else if (d_socket != -1) {
      shutdown(d_socket, SHUT_RDWR);
    }
  }
  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout)
  {
    if (d_conn) {
      return d_conn->read(buffer, bufferSize, readTimeout);
    } else {
      return readn2WithTimeout(d_socket, buffer, bufferSize, readTimeout);
    }
  }
  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout)
  {
    if (d_conn) {
      return d_conn->write(buffer, bufferSize, writeTimeout);
    }
    else {
      return writen2WithTimeout(d_socket, buffer, bufferSize, writeTimeout);
    }
  }

  bool writeSizeAndMsg(const void* buffer, size_t bufferSize, unsigned int writeTimeout)
  {
    if (d_conn) {
      uint16_t size = htons(bufferSize);
      if (d_conn->write(&size, sizeof(size), writeTimeout) != sizeof(size)) {
        return false;
      }
      return (d_conn->write(buffer, bufferSize, writeTimeout) == bufferSize);
    }
    else {
      return sendSizeAndMsgWithTimeout(d_socket, bufferSize, static_cast<const char*>(buffer), writeTimeout, nullptr, nullptr, 0, 0, 0);
    }
  }

private:
  std::unique_ptr<TLSConnection> d_conn{nullptr};
  int d_socket{-1};
};
