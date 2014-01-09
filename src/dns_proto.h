/*
 * $Id: dns_proto.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Jan  9 14:41:31 2014 mstenber
 * Last modified: Thu Jan  9 18:18:04 2014 mstenber
 * Edit time:     6 min
 *
 */

#ifndef DNS_PROTO_H
#define DNS_PROTO_H

#include <libubox/utils.h>

typedef struct __packed dns_msg {
  uint16_t id;
  uint16_t h; /* qr (1), opcode (3), aa, tc, rd, ra */
  /* ra (1), z(3), rcode(4) */
  uint16_t qdcount; /* dns_query's */
  uint16_t ancount; /* dns_rr's */
  uint16_t nscount; /* dns_rr's */
  uint16_t arcount; /* dns_rr's */
} *dns_msg;

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

#endif /* DNS_PROTO_H */
