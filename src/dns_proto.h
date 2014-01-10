/*
 * $Id: dns_proto.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Jan  9 14:41:31 2014 mstenber
 * Last modified: Fri Jan 10 16:55:39 2014 mstenber
 * Edit time:     12 min
 *
 */

#ifndef DNS_PROTO_H
#define DNS_PROTO_H

#include <libubox/utils.h>

typedef struct __packed dns_msg {
  uint16_t id;
  uint16_t h; /* qr, opcode (4), aa, tc, rd */
  /* ra, z(3), rcode(4) */
  uint16_t qdcount; /* dns_query's */
  uint16_t ancount; /* dns_rr's */
  uint16_t nscount; /* dns_rr's */
  uint16_t arcount; /* dns_rr's */
} *dns_msg;

#define DNS_H_QR (1 << 15)
#define DNS_H_OPCODE(x) (((x) & 0xF) << 11)
#define DNS_H_AA (1 << 10)
#define DNS_H_TC (1 << 9)
#define DNS_H_RD (1 << 8)
#define DNS_H_RA (1 << 7)
#define DNS_H_Z(x) (((x) & 0x7) << 4)
#define DNS_H_RCODE(x) ((x) & 0xF))

/* name does not exist (meaningful only from authoritative) */
#define DNS_RCODE_NXDOMAIN 3

/* name server does not support requested kind of query */
#define DNS_RCODE_NOTIMP 4

typedef struct __packed dns_query {
  /* Preceded by label list */
  uint16_t qtype;
  uint16_t qclass;
} *dns_query;

typedef struct __packed dns_rr {
  /* Preceded by label list */
  uint16_t rrtype;
  uint16_t rrclass;
  uint32_t ttl;
  uint16_t rdlen;
  uint8_t rdata[];
} *dns_rr;

typedef struct __packed dns_rdata_srv {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
} *dns_rdata_srv;

#endif /* DNS_PROTO_H */
