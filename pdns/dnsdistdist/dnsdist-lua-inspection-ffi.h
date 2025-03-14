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

typedef struct dnsdist_ffi_stat_node_t dnsdist_ffi_stat_node_t;

uint64_t dnsdist_ffi_stat_node_get_queries_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_noerrors_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_nxdomains_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_servfails_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_drops_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_bytes(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_hits(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
unsigned int dnsdist_ffi_stat_node_get_labels_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
void dnsdist_ffi_stat_node_get_full_name_raw(const dnsdist_ffi_stat_node_t* node, const char** name, size_t* nameSize) __attribute__((visibility("default")));

unsigned int dnsdist_ffi_stat_node_get_children_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));

/* Note that dnsdist_ffi_stat_node_get_children_* methods return the sum of
   the queries or responses received for the children of a node AND the node
   itself. It's quite unexpected but breaking the existing behaviour now would be painful.
*/
uint64_t dnsdist_ffi_stat_node_get_children_queries_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_children_noerrors_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_children_nxdomains_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_children_servfails_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_children_drops_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_children_bytes_count(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));
uint64_t dnsdist_ffi_stat_node_get_children_hits(const dnsdist_ffi_stat_node_t* node) __attribute__((visibility("default")));

void dnsdist_ffi_state_node_set_reason(dnsdist_ffi_stat_node_t* node, const char* reason, size_t reasonSize) __attribute__((visibility("default")));
void dnsdist_ffi_state_node_set_action(dnsdist_ffi_stat_node_t* node, int blockAction) __attribute__((visibility("default")));

typedef enum
{
  dnsdist_ffi_dynamic_block_type_nmt = 0,
  dnsdist_ffi_dynamic_block_type_smt = 1,
} dnsdist_ffi_dynamic_block_type;
