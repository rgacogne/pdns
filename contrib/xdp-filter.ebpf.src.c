#include <stdbool.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xdp.h"

#define DISABLE_LOGGING 1
#define UseXsk 1

#if !defined(DDIST_MAPS_SIZE)
#define DDIST_MAPS_SIZE 1024
#endif /* DDIST_MAPS_SIZE */

#if !defined(DDIST_MAX_NUMBER_OF_QUEUES)
#define DDIST_MAX_NUMBER_OF_QUEUES 256
#endif /* DDIST_MAX_NUMBER_OF_QUEUES */

// /sys/fs/bpf/dnsdist/addr-v4
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, DDIST_MAPS_SIZE);
  __uint(key_size, sizeof(uint32_t));
  __uint(value_size, sizeof(struct map_value));
} v4filter SEC(".maps");

// /sys/fs/bpf/dnsdist/addr-v6
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, DDIST_MAPS_SIZE);
  __uint(key_size, sizeof(struct in6_addr));
  __uint(value_size, sizeof(struct map_value));
} v6filter SEC(".maps");

// /sys/fs/bpf/dnsdist/qnames
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, DDIST_MAPS_SIZE);
  __uint(key_size, sizeof(struct dns_qname));
  __uint(value_size, sizeof(struct map_value));
} qnamefilter SEC(".maps");

#ifndef DISABLE_LOGGING
// /sys/fs/bpf/dnsdist/progs
struct {
  __uint(type, BPF_MAP_TYPE_PROG);
  __uint(max_entries, 2U);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} progsarray SEC(".maps");
#endif /* DISABLE_LOGGING */

// /sys/fs/bpf/dnsdist/cdir4
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, DDIST_MAPS_SIZE);
  __uint(key_size, sizeof(struct CIDR4));
  __uint(value_size, sizeof(struct map_value));
} cidr4filter SEC(".maps");

// /sys/fs/bpf/dnsdist/cdir6
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, DDIST_MAPS_SIZE);
  __uint(key_size, sizeof(struct CIDR6));
  __uint(value_size, sizeof(struct map_value));
} cidr6filter SEC(".maps");

#ifdef UseXsk
// /sys/fs/bpf/dnsdist/xskmap
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, DDIST_MAX_NUMBER_OF_QUEUES);
  __type(key, uint32_t);
  __type(value, uint32_t);
} xsk_map SEC(".maps");

// /sys/fs/bpf/dnsdist/xsk-destinations-v4
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, DDIST_MAPS_SIZE);
  __type(key, struct IPv4AndPort);
  __type(value, bool);
} xskDestinationsV4 SEC(".maps");

// /sys/fs/bpf/dnsdist/xsk-destinations-v6
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, DDIST_MAPS_SIZE);
  __type(key, struct IPv6AndPort);
  __type(value, bool);
} xskDestinationsV6 SEC(".maps");
#endif /* UseXsk */

#define COMPARE_PORT(x, p) ((x) == bpf_htons(p))

/*
 * Recalculate the checksum
 * Copyright 2020, NLnet Labs, All rights reserved.
 */
static inline void update_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val)
{
  uint32_t new_csum_value;
  uint32_t new_csum_comp;
  uint32_t undo;

  undo = ~((uint32_t)*csum) + ~((uint32_t)old_val);
  new_csum_value = undo + (undo < ~((uint32_t)old_val)) + (uint32_t)new_val;
  new_csum_comp = new_csum_value + (new_csum_value < ((uint32_t)new_val));
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  *csum = (uint16_t)~new_csum_comp;
}

/*
 * Set the TC bit and swap UDP ports
 * Copyright 2020, NLnet Labs, All rights reserved.
 */
static inline void set_tc_bit(struct udphdr* udp, struct dnshdr* dns)
{
  uint16_t old_val = dns->flags.as_value;

  // change the DNS flags
  dns->flags.as_bits_and_pieces.ad = 0;
  dns->flags.as_bits_and_pieces.qr = 1;
  dns->flags.as_bits_and_pieces.tc = 1;

  // change the UDP destination to the source
  uint16_t tmp = udp->dest;
  udp->dest = udp->source;
  udp->source = tmp;

  // calculate and write the new checksum
  update_checksum(&udp->check, old_val, dns->flags.as_value);
}

/*
 * Check DNS QName
 * Returns PASS if message needs to go through (i.e. pass)
 *         TC if (modified) message needs to be replied
 *         DROP if message needs to be blocked
 */
static inline struct map_value* check_qname(struct cursor* c)
{
  struct dns_qname qkey = {0};
  uint8_t qname_byte;
  uint16_t qtype;
  int length = 0;

  for (int i = 0; i < 255; i++) {
    if (bpf_probe_read_kernel(&qname_byte, sizeof(qname_byte), c->pos)) {
      return NULL;
    }
    c->pos += 1;
    if (length == 0) {
      if (qname_byte == 0 || qname_byte > 63) {
        break;
      }
      length += qname_byte;
    }
    else {
      length--;
    }
    if (qname_byte >= 'A' && qname_byte <= 'Z') {
      qkey.qname[i] = qname_byte + ('a' - 'A');
    }
    else {
      qkey.qname[i] = qname_byte;
    }
  }

  // if the last read qbyte is not 0 incorrect QName format), return PASS
  if (qname_byte != 0) {
    return NULL;
  }

  // get QType
  if (bpf_probe_read_kernel(&qtype, sizeof(qtype), c->pos)) {
    return NULL;
  }

  // check if Qname/Qtype is blocked
  qkey.qtype = bpf_htons(qtype);
  struct map_value* value = bpf_map_lookup_elem(&qnamefilter, &qkey);
  if (value) {
    return value;
  }

  // check with Qtype 65535 (*)
  qkey.qtype = 65535;

  return bpf_map_lookup_elem(&qnamefilter, &qkey);
}

/*
 * Parse IPv4 DNS message.
 * Returns XDP_PASS if message needs to go through (i.e. pass)
 *         XDP_REDIRECT if message needs to be redirected (for AF_XDP, which needs to be translated to the caller into XDP_PASS outside of the AF_XDP)
 *         XDP_TX if (modified) message needs to be replied
 *         XDP_DROP if message needs to be blocked
 */
static inline enum xdp_action parseIPV4([[maybe_unused]] struct xdp_md* ctx, struct cursor* c)
{
  struct iphdr* ipv4;
  struct udphdr* udp = NULL;
  struct dnshdr* dns = NULL;
  if (!(ipv4 = parse_iphdr(c))) {
    return XDP_PASS;
  }
  switch (ipv4->protocol) {
  case IPPROTO_UDP: {
    if (!(udp = parse_udphdr(c))) {
      return XDP_PASS;
    }
#ifdef UseXsk
    struct IPv4AndPort v4Dest;
    memset(&v4Dest, 0, sizeof(v4Dest));
    v4Dest.port = udp->dest;
    v4Dest.addr = ipv4->daddr;
    if (!bpf_map_lookup_elem(&xskDestinationsV4, &v4Dest)) {
      return XDP_PASS;
    }
#else /* UseXsk */
#warning we should use a (per-queue? or per XskSocket object?) map to store the ports we are willing to accept
    //if (!IN_DNS_PORT_SET(udp->dest)) {
    //  return XDP_PASS;
    //}
#endif /* UseXsk */
    if (!(dns = parse_dnshdr(c))) {
      return XDP_DROP;
    }
    break;
  }

#ifdef UseXsk
  case IPPROTO_TCP: {
    return XDP_PASS;
  }
#endif /* UseXsk */

  default:
    return XDP_PASS;
  }

  struct CIDR4 key;
  key.addr = bpf_htonl(ipv4->saddr);

  // if the address is blocked, perform the corresponding action
  struct map_value* value = bpf_map_lookup_elem(&v4filter, &key.addr);
  if (value) {
    goto res;
  }

  key.cidr = 32;
  key.addr = bpf_htonl(key.addr);
  value = bpf_map_lookup_elem(&cidr4filter, &key);
  if (value) {
    goto res;
  }

  // ignore the DF flag
  const uint16_t fragMask = bpf_htons(~(1 << 14));
  uint16_t frag = ipv4->frag_off & fragMask;
  if (frag != 0) {
    // MF flag is set, or Fragment Offset is != 0
    return XDP_PASS;
  }

  if (dns) {
    value = check_qname(c);
  }
  if (value) {
  res:
    __sync_fetch_and_add(&value->counter, 1);
    if (value->action == TC && udp && dns) {
      set_tc_bit(udp, dns);
      // swap src/dest IP addresses
      uint32_t swap_ipv4 = ipv4->daddr;
      ipv4->daddr = ipv4->saddr;
      ipv4->saddr = swap_ipv4;

#ifndef DISABLE_LOGGING
      progsarray.call(ctx, 1);
#endif /* DISABLE_LOGGING */
      return XDP_TX;
    }

    if (value->action == DROP) {
#ifndef DISABLE_LOGGING
      progsarray.call(ctx, 0);
#endif /* DISABLE_LOGGING */
      return XDP_DROP;
    }
  }

  return XDP_REDIRECT;
}

/*
 * Parse IPv6 DNS message.
 * Returns XDP_PASS if message needs to go through (i.e. pass)
 *         XDP_REDIRECT if message needs to be redirected (for AF_XDP, which needs to be translated to the caller into XDP_PASS outside of the AF_XDP)
 *         XDP_TX if (modified) message needs to be replied
 *         XDP_DROP if message needs to be blocked
 */
static inline enum xdp_action parseIPV6([[maybe_unused]] struct xdp_md* ctx, struct cursor* c)
{
  struct ipv6hdr* ipv6;
  struct udphdr* udp = NULL;
  struct dnshdr* dns = NULL;
  if (!(ipv6 = parse_ipv6hdr(c))) {
    return XDP_PASS;
  }
  switch (ipv6->nexthdr) {
  case IPPROTO_UDP: {
    if (!(udp = parse_udphdr(c))) {
      return XDP_PASS;
    }
#ifdef UseXsk
    struct IPv6AndPort v6Dest;
    memset(&v6Dest, 0, sizeof(v6Dest));
    v6Dest.port = udp->dest;
    memcpy(&v6Dest.addr, &ipv6->daddr, sizeof(v6Dest.addr));
    if (!bpf_map_lookup_elem(&xskDestinationsV6, &v6Dest)) {
      return XDP_PASS;
    }
#else /* UseXsk */
#warning we should use a (per-queue? or per XskSocket object?) map to store the ports we are willing to accept
    //if (!IN_DNS_PORT_SET(udp->dest)) {
    //  return XDP_PASS;
    //}
#endif /* UseXsk */
  if (!(dns = parse_dnshdr(c))) {
      return XDP_DROP;
    }
    break;
  }

#ifdef UseXsk
  case IPPROTO_TCP: {
    return XDP_PASS;
  }
#endif /* UseXsk */

  default:
    return XDP_PASS;
  }

  struct CIDR6 key;
  key.addr = ipv6->saddr;

  // if the address is blocked, perform the corresponding action
  struct map_value* value = bpf_map_lookup_elem(&v6filter, &key.addr);
  if (value) {
    goto res;
  }

  key.cidr = 128;
  value = bpf_map_lookup_elem(&cidr6filter, &key);
  if (value) {
    goto res;
  }

  if (dns) {
    value = check_qname(c);
  }
  if (value) {
  res:
    __sync_fetch_and_add(&value->counter, 1);
    if (value->action == TC && udp && dns) {
      set_tc_bit(udp, dns);
      // swap src/dest IP addresses
      struct in6_addr swap_ipv6 = ipv6->daddr;
      ipv6->daddr = ipv6->saddr;
      ipv6->saddr = swap_ipv6;
#ifndef DISABLE_LOGGING
      progsarray.call(ctx, 1);
#endif /* DISABLE_LOGGING */
      return XDP_TX;
    }
    if (value->action == DROP) {
#ifndef DISABLE_LOGGING
      progsarray.call(ctx, 0);
#endif /* DISABLE_LOGGING */
      return XDP_DROP;
    }
  }
  return XDP_REDIRECT;
}

SEC("xdp")
int xdp_dns_filter(struct xdp_md* ctx)
{
  // store variables
  struct cursor   c;
  struct ethhdr  *eth;
  uint16_t        eth_proto;
  enum xdp_action r;

  // initialise the cursor
  cursor_init(&c, ctx);

  // pass the packet if it is not an ethernet one
  if ((eth = parse_eth(&c, &eth_proto))) {
    // IPv4 packets
    if (eth_proto == bpf_htons(ETH_P_IP)) {
      r = parseIPV4(ctx, &c);
      goto res;
    }
    // IPv6 packets
    else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
      r = parseIPV6(ctx, &c);
      goto res;
    }
    // pass all non-IP packets
    return XDP_PASS;
  }
  return XDP_PASS;
res:
  switch (r) {
  case XDP_REDIRECT:
#ifdef UseXsk
    return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
#else
    return XDP_PASS;
#endif /* UseXsk */
  case XDP_TX: { // swap MAC addresses
    uint8_t swap_eth[ETH_ALEN];
    memcpy(swap_eth, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, swap_eth, ETH_ALEN);
    // bounce the request
    return XDP_TX;
  }
  default:
    return r;
  }
}

char _license[] SEC("license") = "GPL";
