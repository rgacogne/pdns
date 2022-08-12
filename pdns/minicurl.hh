/*
 * MIT License
 *
 * Copyright (c) 2018-2019 powerdns.com bv
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once
#include <string>
#include <curl/curl.h>
#include "iputils.hh"
// turns out 'CURL' is currently typedef for void which means we can't easily forward declare it

class MiniCurl
{
public:
  using MiniCurlHeaders = std::map<std::string, std::string>;

  static void init();

  MiniCurl(const string& useragent="MiniCurl/0.0");
  ~MiniCurl();
  MiniCurl& operator=(const MiniCurl&) = delete;
  std::string getURL(const std::string& str, const ComboAddress* rem=nullptr, const ComboAddress* src=nullptr, int timeout = 2, bool fastopen = false, bool verify = false);
  std::string postURL(const std::string& str, const std::string& postdata, MiniCurlHeaders& headers, int timeout = 2, bool fastopen = false, bool verify = false);
  enum class TimingInfo : uint8_t {
    Connect, /* TCP connection has been established */
    TLSDone, /* TLS session has been set up (handshake done) */
    QueryReadyToBeSent, /* Query is being sent */
    TransferStarted, /* For POST and PUT queries, the payload is being sent. Otherwise the first byte of the response has been received */
    Total /* Response has been fully received */
  };
  /* rrturn the elapsed time, in microseconds, to reach the requested state */
  uint64_t getTimingInfo(TimingInfo) const;
private:
  CURL *d_curl{nullptr};
  static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);
  std::string d_data;
  struct curl_slist* d_header_list = nullptr;
  void setupURL(const std::string& str, const ComboAddress* rem, const ComboAddress* src, int timeout, bool fastopen, bool verify);
  void setHeaders(const MiniCurlHeaders& headers);
  void clearHeaders();
};
