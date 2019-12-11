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

#include "dnsdist-lua-ffi.hh"
#include "dnsdist-ecs.hh"

uint16_t dnsdist_ffi_dnsquestion_get_qtype(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->qtype;
}

uint16_t dnsdist_ffi_dnsquestion_get_qclass(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->qclass;
}

static void dnsdist_ffi_comboaddress_to_raw(const ComboAddress& ca, const void** addr, size_t* addrSize)
{
  if (ca.isIPv4()) {
    *addr = &ca.sin4.sin_addr.s_addr;
    *addrSize = sizeof(ca.sin4.sin_addr.s_addr);
  }
  else {
    *addr = &ca.sin6.sin6_addr.s6_addr;
    *addrSize = sizeof(ca.sin6.sin6_addr.s6_addr);
  }
}

void dnsdist_ffi_dnsquestion_get_localaddr(const dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize)
{
  dnsdist_ffi_comboaddress_to_raw(*dq->dq->local, addr, addrSize);
}

void dnsdist_ffi_dnsquestion_get_remoteaddr(const dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize)
{
  dnsdist_ffi_comboaddress_to_raw(*dq->dq->remote, addr, addrSize);
}

uint16_t dnsdist_ffi_dnsquestion_get_local_port(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->local->getPort();
}

uint16_t dnsdist_ffi_dnsquestion_get_remote_port(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->remote->getPort();
}

void dnsdist_ffi_dnsquestion_get_qname_raw(const dnsdist_ffi_dnsquestion_t* dq, const char** qname, size_t* qnameSize)
{
  const auto& storage = dq->dq->qname->getStorage();
  *qname = storage.data();
  *qnameSize = storage.size();
}

int dnsdist_ffi_dnsquestion_get_rcode(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->dh->rcode;
}

void* dnsdist_ffi_dnsquestion_get_header(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->dh;
}

uint16_t dnsdist_ffi_dnsquestion_get_len(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->len;
}

size_t dnsdist_ffi_dnsquestion_get_size(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->size;
}

uint8_t dnsdist_ffi_dnsquestion_get_opcode(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->dh->opcode;
}

bool dnsdist_ffi_dnsquestion_get_tcp(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->tcp;
}

bool dnsdist_ffi_dnsquestion_get_skip_cache(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->skipCache;
}

bool dnsdist_ffi_dnsquestion_get_use_ecs(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->useECS;
}

bool dnsdist_ffi_dnsquestion_get_add_xpf(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->addXPF;
}

bool dnsdist_ffi_dnsquestion_get_ecs_override(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ecsOverride;
}

uint16_t dnsdist_ffi_dnsquestion_get_ecs_prefix_length(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ecsPrefixLength;
}

bool dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->tempFailureTTL != boost::none;
}

uint32_t dnsdist_ffi_dnsquestion_get_temp_failure_ttl(const dnsdist_ffi_dnsquestion_t* dq)
{
  if (dq->dq->tempFailureTTL) {
    return *dq->dq->tempFailureTTL;
  }
  return 0;
}

bool dnsdist_ffi_dnsquestion_get_do(const dnsdist_ffi_dnsquestion_t* dq)
{
  return getEDNSZ(*dq->dq) & EDNS_HEADER_FLAG_DO;
}

void dnsdist_ffi_dnsquestion_get_sni(const dnsdist_ffi_dnsquestion_t* dq, const char** sni, size_t* sniSize)
{
  *sniSize = dq->dq->sni.size();
  *sni = dq->dq->sni.c_str();
}

const char* dnsdist_ffi_dnsquestion_get_tag(const dnsdist_ffi_dnsquestion_t* dq, const char* label)
{
  const char * result = nullptr;

  if (dq->dq->qTag != nullptr) {
    const auto it = dq->dq->qTag->find(label);
    if (it != dq->dq->qTag->cend()) {
      result = it->second.c_str();
    }
  }

  return result;
}

const char* dnsdist_ffi_dnsquestion_get_http_path(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpPath) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpPath = dq->dq->du->getHTTPPath();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpPath) {
    return dq->httpPath->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_query_string(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpQueryString) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpQueryString = dq->dq->du->getHTTPQueryString();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpQueryString) {
    return dq->httpQueryString->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_host(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpHost) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpHost = dq->dq->du->getHTTPHost();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpHost) {
    return dq->httpHost->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_scheme(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpScheme) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpScheme = dq->dq->du->getHTTPScheme();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpScheme) {
    return dq->httpScheme->c_str();
  }
  return nullptr;
}

static void fill_edns_option(const EDNSOptionViewValue& value, dnsdist_ednsoption_t& option)
{
  option.len = value.size;
  option.data = nullptr;

  if (value.size > 0) {
    option.data = value.content;
  }
}

// returns the length of the resulting 'out' array. 'out' is not set if the length is 0
size_t dnsdist_ffi_dnsquestion_get_edns_options(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ednsoption_t** out)
{
  if (dq->dq->ednsOptions == nullptr) {
    parseEDNSOptions(*(dq->dq));
  }

  size_t totalCount = 0;
  for (const auto& option : *dq->dq->ednsOptions) {
    totalCount += option.second.values.size();
  }

  dq->ednsOptionsVect.clear();
  dq->ednsOptionsVect.resize(totalCount);
  size_t pos = 0;
  for (const auto& option : *dq->dq->ednsOptions) {
    for (const auto& entry : option.second.values) {
      fill_edns_option(entry, dq->ednsOptionsVect.at(pos));
      dq->ednsOptionsVect.at(pos).optionCode = option.first;
      pos++;
    }
  }

  if (totalCount > 0) {
    *out = dq->ednsOptionsVect.data();
  }

  return totalCount;
}

size_t dnsdist_ffi_dnsquestion_get_http_headers(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_http_header_t** out)
{
  if (dq->dq->du == nullptr) {
    return 0;
  }

#ifdef HAVE_DNS_OVER_HTTPS
  dq->httpHeaders = dq->dq->du->getHTTPHeaders();
  dq->httpHeadersVect.clear();
  dq->httpHeadersVect.resize(dq->httpHeaders.size());
  size_t pos = 0;
  for (const auto& header : dq->httpHeaders) {
    dq->httpHeadersVect.at(pos).name = header.first.c_str();
    dq->httpHeadersVect.at(pos).value = header.second.c_str();
    ++pos;
  }

  if (!dq->httpHeadersVect.empty()) {
    *out = dq->httpHeadersVect.data();
  }

  return dq->httpHeadersVect.size();
#else
  return 0;
#endif
}

size_t dnsdist_ffi_dnsquestion_get_tag_array(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_tag_t** out)
{
  if (dq->dq->qTag == nullptr || dq->dq->qTag->size() == 0) {
    return 0;
  }

  dq->tagsVect.clear();
  dq->tagsVect.resize(dq->dq->qTag->size());
  size_t pos = 0;

  for (const auto& tag : *dq->dq->qTag) {
    auto& entry = dq->tagsVect.at(pos);
    entry.name = tag.first.c_str();
    entry.value = tag.second.c_str();
    ++pos;
  }


  if (!dq->tagsVect.empty()) {
    *out = dq->tagsVect.data();
  }

  return dq->tagsVect.size();
}

void dnsdist_ffi_dnsquestion_set_result(dnsdist_ffi_dnsquestion_t* dq, const char* str, size_t strSize)
{
  dq->result = std::string(str, strSize);
}

void dnsdist_ffi_dnsquestion_set_http_response(dnsdist_ffi_dnsquestion_t* dq, uint16_t statusCode, const char* body, const char* contentType)
{
  if (dq->dq->du == nullptr) {
    return;
  }

#ifdef HAVE_DNS_OVER_HTTPS
  dq->dq->du->setHTTPResponse(statusCode, body, contentType);
  dq->dq->dh->qr = true;
#endif
}

void dnsdist_ffi_dnsquestion_set_rcode(dnsdist_ffi_dnsquestion_t* dq, int rcode)
{
  dq->dq->dh->rcode = rcode;
  dq->dq->dh->qr = true;
}

void dnsdist_ffi_dnsquestion_set_len(dnsdist_ffi_dnsquestion_t* dq, uint16_t len)
{
  dq->dq->len = len;
}

void dnsdist_ffi_dnsquestion_set_skip_cache(dnsdist_ffi_dnsquestion_t* dq, bool skipCache)
{
  dq->dq->skipCache = skipCache;
}

void dnsdist_ffi_dnsquestion_set_use_ecs(dnsdist_ffi_dnsquestion_t* dq, bool useECS)
{
  dq->dq->useECS = useECS;
}

void dnsdist_ffi_dnsquestion_set_ecs_override(dnsdist_ffi_dnsquestion_t* dq, bool ecsOverride)
{
  dq->dq->ecsOverride = ecsOverride;
}

void dnsdist_ffi_dnsquestion_set_ecs_prefix_length(dnsdist_ffi_dnsquestion_t* dq, uint16_t ecsPrefixLength)
{
  dq->dq->ecsPrefixLength = ecsPrefixLength;
}

void dnsdist_ffi_dnsquestion_set_temp_failure_ttl(dnsdist_ffi_dnsquestion_t* dq, uint32_t tempFailureTTL)
{
  dq->dq->tempFailureTTL = tempFailureTTL;
}

void dnsdist_ffi_dnsquestion_unset_temp_failure_ttl(dnsdist_ffi_dnsquestion_t* dq)
{
  dq->dq->tempFailureTTL = boost::none;
}

void dnsdist_ffi_dnsquestion_set_tag(dnsdist_ffi_dnsquestion_t* dq, const char* label, const char* value)
{
  if (!dq->dq->qTag) {
    dq->dq->qTag = std::make_shared<QTag>();
  }

  dq->dq->qTag->insert({label, value});
}

size_t dnsdist_ffi_dnsquestion_get_trailing_data(dnsdist_ffi_dnsquestion_t* dq, const char** out)
{
  dq->trailingData = dq->dq->getTrailingData();
  if (!dq->trailingData.empty()) {
    *out = dq->trailingData.data();
  }

  return dq->trailingData.size();
}

bool dnsdist_ffi_dnsquestion_set_trailing_data(dnsdist_ffi_dnsquestion_t* dq, const char* data, size_t dataLen)
{
  return dq->dq->setTrailingData(std::string(data, dataLen));
}

void dnsdist_ffi_dnsquestion_send_trap(dnsdist_ffi_dnsquestion_t* dq, const char* reason, size_t reasonLen)
{
  if (g_snmpAgent && g_snmpTrapsEnabled) {
    g_snmpAgent->sendDNSTrap(*dq->dq, std::string(reason, reasonLen));
  }
}

size_t dnsdist_ffi_servers_list_get_count(const dnsdist_ffi_servers_list_t* list)
{
  return list->ffiServers.size();
}

void dnsdist_ffi_servers_list_get_server(const dnsdist_ffi_servers_list_t* list, size_t idx, const dnsdist_ffi_server_t** out)
{
  *out = &list->ffiServers.at(idx);
}

uint64_t dnsdist_ffi_server_get_outstanding(const dnsdist_ffi_server_t* server)
{
  return server->server->outstanding;
}

int dnsdist_ffi_server_get_weight(const dnsdist_ffi_server_t* server)
{
  return server->server->weight;
}

int dnsdist_ffi_server_get_order(const dnsdist_ffi_server_t* server)
{
  return server->server->order;
}

bool dnsdist_ffi_server_is_up(const dnsdist_ffi_server_t* server)
{
  return server->server->isUp();
}

const char* dnsdist_ffi_server_get_name(const dnsdist_ffi_server_t* server)
{
  return server->server->getName().c_str();
}

const char* dnsdist_ffi_server_get_name_with_addr(const dnsdist_ffi_server_t* server)
{
  return server->server->getNameWithAddr().c_str();
}

const std::string& getLuaFFIWrappers()
{
  static const std::string interface =
#include "dnsdist-lua-ffi-interface.inc"
    ;
  static const std::string code = R"FFICodeContent(
  local ffi = require("ffi")
  local C = ffi.C

  ffi.cdef[[
)FFICodeContent" + interface + R"FFICodeContent(
  ]]

function _get_ffi_dq(ffi_ref)
  local function getNewEDNSOptionView(value)
    local newOption = {
      values = { value }
    }
    local optionMT = {
      __index = function(t, key)
        if key == 'count' then
          return function(t)
            return #t.values
          end
        end
        if key == 'getValues' then
          return function(t)
            return t.values
          end
        end
      end
    }
    setmetatable(newOption, optionMT)
    return newOption
  end
  local mt = {
    __index = function(t, key)
      if key == 'ecsOverride' then
        return C.dnsdist_ffi_dnsquestion_get_ecs_override(t.ref)
      end
      if key == 'ecsPrefixLength' then
        return C.dnsdist_ffi_dnsquestion_get_ecs_prefix_length(t.ref)
      end
      if key == 'getDO' then
        return function(t)
          return C.dnsdist_ffi_dnsquestion_get_do(t.ref)
        end
      end
      if key == 'getEDNSOptions' then
        return function(t)
          local ret_ptr = ffi.new("const dnsdist_ednsoption_t *[1]")
          local ret_ptr_param = ffi.cast("const dnsdist_ednsoption_t **", ret_ptr)
          local count = tonumber(C.dnsdist_ffi_dnsquestion_get_edns_options(t.ref, ret_ptr_param))
          local result = {}
          if count > 0 then
            for idx = 0, count-1 do
              local option = ret_ptr[0][idx];
              if result[tonumber(option.optionCode)] == nil then
                result[tonumber(option.optionCode)] = getNewEDNSOptionView(ffi.string(option.data, option.len))
              else
                table.insert(result[tonumber(option.optionCode)].values, ffi.string(option.data, option.len))
              end
            end
          end
          return result
        end
      end
      if key == 'getHTTPHeaders' then
        return function(t)
          local ret_ptr = ffi.new("const dnsdist_http_header_t *[1]")
          local ret_ptr_param = ffi.cast("const dnsdist_http_header_t **", ret_ptr)
          local count = tonumber(C.dnsdist_ffi_dnsquestion_get_http_headers(t.ref, ret_ptr_param))
          local result = {}
          if count > 0 then
            for idx = 0, count-1 do
              local header = ret_ptr[0][idx];
              result[ffi.string(header.name)] = ffi.string(header.value)
            end
          end
          return result
        end
      end
      if key == 'getHTTPPath' then
        return function(t)
          local val = C.dnsdist_ffi_dnsquestion_get_http_path(t.ref)
          if val then
            return ffi.string(val)
          end
          return nil
        end
      end
      if key == 'getHTTPQueryString' then
        return function(t)
          local val = C.dnsdist_ffi_dnsquestion_get_http_query_string(t.ref)
          if val then
            return ffi.string(val)
          end
          return nil
        end
      end
      if key == 'getHTTPHost' then
        return function(t)
          local val = C.dnsdist_ffi_dnsquestion_get_http_host(t.ref)
          if val then
            return ffi.string(val)
          end
          return nil
        end
      end
      if key == 'getHTTPScheme' then
        return function(t)
          local val = C.dnsdist_ffi_dnsquestion_get_http_scheme(t.ref)
          if val then
            return ffi.string(val)
          end
          return nil
        end
      end
      if key == 'getServerNameIndication' then
        return function(t)
          local ret_ptr = ffi.new("const char *[1]")
          local ret_ptr_param = ffi.cast("const char **", ret_ptr)
          local ret_size = ffi.new("size_t[1]")
          local ret_size_param = ffi.cast("size_t*", ret_size)
          C.dnsdist_ffi_dnsquestion_get_sni(t.ref, ret_ptr_param, ret_size_param)
          if ret_size[0] == 0 then
            return nil
          end
          return ffi.string(ret_ptr[0], ret_size[0])
        end
      end
      if key == 'getTag' then
        return function(t, label)
          local buf = ffi.new("char[?]", #label + 1)
          ffi.copy(buf, label)
          local val = C.dnsdist_ffi_dnsquestion_get_tag(t.ref, buf)
          if val then
            return ffi.string(val)
          end
          return nil
        end
      end
      if key == 'getTagArray' then
        return function(t)
          local result = {}
          local ret_ptr = ffi.new("const dnsdist_tag_t *[1]")
          local ret_ptr_param = ffi.cast("const dnsdist_tag_t **", ret_ptr)
          local count = tonumber(C.dnsdist_ffi_dnsquestion_get_tag_array(t.ref, ret_ptr_param))
          local result = {}
          if count > 0 then
            for idx = 0, count-1 do
              local tag = ret_ptr[0][idx]
              result[ffi.string(tag.name)] = ffi.string(tag.value)
            end
          end
          return result
        end
      end
      if key == 'getTrailingData' then
        return function(t)
          local ret_ptr = ffi.new("const char *[1]")
          local ret_ptr_param = ffi.cast("const char **", ret_ptr)
          local len = tonumber(C.dnsdist_ffi_dnsquestion_get_trailing_data(t.ref, ret_ptr_param))
          return ffi.string(ret_ptr[0], len)
        end
      end
      if key == 'len' then
        return tonumber(C.dnsdist_ffi_dnsquestion_get_len(t.ref))
      end
      if key == 'localaddr' then
        local ret_ptr = ffi.new("void *[1]")
        local ret_ptr_param = ffi.cast("const void **", ret_ptr)
        local ret_size = ffi.new("size_t[1]")
        local ret_size_param = ffi.cast("size_t*", ret_size)
        C.dnsdist_ffi_dnsquestion_get_localaddr(t.ref, ret_ptr_param, ret_size_param)
        local port = C.dnsdist_ffi_dnsquestion_get_local_port(t.ref)
        return newCAFromRaw(ffi.string(ret_ptr[0], ret_size[0]), port)
      end
      if key == 'remoteaddr' then
        local ret_ptr = ffi.new("void *[1]")
        local ret_ptr_param = ffi.cast("const void **", ret_ptr)
        local ret_size = ffi.new("size_t[1]")
        local ret_size_param = ffi.cast("size_t*", ret_size)
        C.dnsdist_ffi_dnsquestion_get_remoteaddr(t.ref, ret_ptr_param, ret_size_param)
        local port = C.dnsdist_ffi_dnsquestion_get_remote_port(t.ref)
        return newCAFromRaw(ffi.string(ret_ptr[0], ret_size[0]), port)
      end
      if key == 'opcode' then
        return tonumber(C.dnsdist_ffi_dnsquestion_get_opcode(t.ref))
      end
      if key == 'qname' then
        local ret_ptr = ffi.new("const char *[1]")
        local ret_ptr_param = ffi.cast("const char **", ret_ptr)
        local ret_size = ffi.new("size_t[1]")
        local ret_size_param = ffi.cast("size_t*", ret_size)
        C.dnsdist_ffi_dnsquestion_get_qname_raw(t.ref, ret_ptr_param, ret_size_param)
        return newDNSNameFromRaw(ffi.string(ret_ptr[0], ret_size[0]))
      end
      if key == 'qtype' then
        return tonumber(C.dnsdist_ffi_dnsquestion_get_qtype(t.ref))
      end
      if key == 'qclass' then
        return tonumber(C.dnsdist_ffi_dnsquestion_get_qclass(t.ref))
      end
      if key == 'rcode' then
        return tonumber(C.dnsdist_ffi_dnsquestion_get_rcode(t.ref))
      end
      if key == 'sendTrap' then
        return function(t, reason)
          local reason_buf = ffi.new("char[?]", #reason + 1)
          ffi.copy(reason_buf, reason)
          C.dnsdist_ffi_dnsquestion_send_trap(t.ref, reason_buf, #reason)
        end
      end
      if key == 'setHTTPResponse' then
        return function(t, code, body, content_type)
          local body_buf = ffi.new("char[?]", #body + 1)
          ffi.copy(body_buf, body)
          local content_type_buf = ffi.new("char[?]", #content_type + 1)
          ffi.copy(content_type_buf, content_type)
          C.dnsdist_ffi_dnsquestion_set_http_response(t.ref, code, body_buf, content_type_buf)
        end
      end
      if key == 'setResult' then
        return function(t, value, size)
          local buf = ffi.new("char[?]", size + 1)
          ffi.copy(buf, value, size)
          C.dnsdist_ffi_dnsquestion_set_result(t.ref, buf, size)
        end
      end
      if key == 'setTag' then
        return function(t, label, value)
          local label_buf = ffi.new("char[?]", #label + 1)
          ffi.copy(label_buf, label)
          local value_buf = ffi.new("char[?]", #value + 1)
          ffi.copy(value_buf, value)
          C.dnsdist_ffi_dnsquestion_set_tag(t.ref, label_buf, value_buf)
        end
      end
      if key == 'setTagArray' then
        return function(t, values)
          for label,value in pairs(values) do
            local label_buf = ffi.new("char[?]", #label + 1)
            ffi.copy(label_buf, label)
            local value_buf = ffi.new("char[?]", #value + 1)
            ffi.copy(value_buf, value)
            C.dnsdist_ffi_dnsquestion_set_tag(t.ref, label_buf, value_buf)
          end
        end
      end
      if key == 'setTrailingData' then
        return function(t, data)
          local len = #data
          local data_buf = ffi.new("char[?]", len + 1)
          ffi.copy(data_buf, data, len)
          return C.dnsdist_ffi_dnsquestion_set_trailing_data(t.ref, data_buf, len)
        end
      end
      if key == 'size' then
        return tonumber(C.dnsdist_ffi_dnsquestion_get_size(t.ref))
      end
      if key == 'skipCache' then
        return C.dnsdist_ffi_dnsquestion_get_skip_cache(t.ref)
      end
      if key == 'tcp' then
        return C.dnsdist_ffi_dnsquestion_get_tcp(t.ref)
      end
      if key == 'tempFailureTTL' then
        if C.dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(t.ref) then
          return C.dnsdist_ffi_dnsquestion_get_temp_failure_ttl(t.ref)
        end
        return nil
      end
      if key == 'useECS' then
        return C.dnsdist_ffi_dnsquestion_get_use_ecs(t.ref)
      end
    end,
    __newindex = function(t, key, value)
      if key == 'ecsOverride' then
        C.dnsdist_ffi_dnsquestion_set_ecs_override(t.ref, value)
      end
      if key == 'ecsPrefixLength' then
        C.dnsdist_ffi_dnsquestion_set_ecs_prefix_length(t.ref, value)
      end
      if key == 'len' then
        C.dnsdist_ffi_dnsquestion_set_len(t.ref, value)
      end
      if key == 'rcode' then
        C.dnsdist_ffi_dnsquestion_set_rcode(t.ref, value)
      end
      if key == 'skipCache' then
        C.dnsdist_ffi_dnsquestion_set_skip_cache(t.ref, value)
      end
      if key == 'tempFailureTTL' then
        if value  == nil then
          C.dnsdist_ffi_dnsquestion_unset_temp_failure_ttl(t.ref)
        else
          C.dnsdist_ffi_dnsquestion_set_temp_failure_ttl(t.ref, value)
        end
      end
      if key == 'useECS' then
        C.dnsdist_ffi_dnsquestion_set_use_ecs(t.ref, value)
      end
    end,
  }
  local t = {
    ref = ffi_ref
  }
  setmetatable(t, mt)
  return t
end

function LuaRule(f)
  function wrapper(ffi_ref)
    local dq = _get_ffi_dq(ffi_ref)
    ret, code = f(dq)
    if code then
      local buf = ffi.new("char[?]", #code + 1)
      ffi.copy(buf, code)
      C.dnsdist_ffi_dnsquestion_set_result(ffi_ref, code, #code)
    end
    return ret
  end
  return LuaFFIRule(wrapper)
end

function LuaAction(f)
  function wrapper(ffi_ref)
    local dq = _get_ffi_dq(ffi_ref)
    ret, code = f(dq)
    if code then
      local buf = ffi.new("char[?]", #code + 1)
      ffi.copy(buf, code)
      C.dnsdist_ffi_dnsquestion_set_result(ffi_ref, code, #code)
    end
    return ret
  end
  return LuaFFIAction(wrapper)
end

)FFICodeContent";
  return code;
}
