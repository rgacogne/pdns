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

extern "C" {
  typedef struct pdns_ffi_param pdns_ffi_param_t;

  typedef struct pdns_ednsoption {
    uint32_t  options;
    uint32_t  len;
    void*     data;
  } pdns_ednsoption_t;

  const char* pdns_ffi_param_get_qname(const pdns_ffi_param_t* ref);
  uint16_t pdns_ffi_param_get_qtype(const pdns_ffi_param_t* ref);
  const char* pdns_ffi_param_get_remote(const pdns_ffi_param_t* ref);
  uint16_t pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref);
  const char* pdns_ffi_param_get_local(const pdns_ffi_param_t* ref);
  uint16_t pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref);
  const char* pdns_ffi_param_get_edns_cs(const pdns_ffi_param_t* ref);
  uint8_t pdns_ffi_param_get_edns_cs_source_mask(const pdns_ffi_param_t* ref);

  // allocate and returns length of result 'out' array
  size_t pdns_ffi_param_edns_option(const pdns_ffi_param_t *ref, uint16_t optioncode, pdns_ednsoption_t** out);

  void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag);
  void pdns_ffi_param_add_policytag(pdns_ffi_param_t *ref, const char* name);
  void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name);
  void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name);
  void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name);
  void pdns_ffi_param_set_data(pdns_ffi_param_t* ref, LuaContext::LuaObject& data);
}
