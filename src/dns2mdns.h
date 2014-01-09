/*
 * $Id: dns2mdns.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:23:19 2014 mstenber
 * Last modified: Thu Jan  9 12:50:06 2014 mstenber
 * Edit time:     36 min
 *
 */

#ifndef DNS2MDNS_H
#define DNS2MDNS_H

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <dns_sd.h>

/* If mdns claims TTL longer than this, we provide smaller one anyway,
 * as there's no invalidation mechanism available. */
#define MAXIMUM_MDNS_TO_DNS_TTL 120

/* How many milliseconds can we wait for results until we're done?
 * MDNS operates on sub-second speed, and some DNS clients starts
 * resending at second. Sigh. */
#define MAXIMUM_REQUEST_DURATION_IN_MS 500

typedef struct ohp_rr {
  struct list_head head;

  /* Name has to match query it is within -> not included. */
  uint16_t rrtype;
  uint16_t rdlen;
  uint32_t ttl;

  uint8_t rdata[];
} *ohp_rr;

typedef struct ohp_query {
  struct list_head head;

  /*
   * This is the DNS-SD version, not MDNS version of query. Conversion
   * between DNS and MDNS happens on the go.
   */
  char *query;
  uint16_t qtype;

  /* Pointer to the mDNSResponder client context (dns_sd.h) for the
   * query we are runnning (if any). */
  DNSServiceRef service;

  /* Backpointer to the request we are in. */
  struct ohp_request *request;

  /* The results of the particular (sub-)query. */
  struct list_head rrs;
} *ohp_query;


/* Shared structure between this + main ohp loop. */
typedef struct ohp_request {
  struct list_head head;
  struct uloop_timeout timeout;

  /* Information from the DNS request by client. */
  uint16_t dnsid;
  size_t maxlen;
  bool udp;

  /* List of sub-queries. The first query is the 'main' one, and the
   * rest 'additional records' ones. */
  struct list_head queries;

  /* Number of running queries. */
  int running;

  /* Have we sent a response already? (refactor this to be rr-specific
   * in LLQ case). */
  bool sent;

  /* Used interface (if any; reverse queries we do on all interfaces
   * and do mapping based on result. the first result 'glues' the
   * interface, though) */
  struct d2m_interface_struct *interface;
} *ohp_request;;

/*
 * This module handles actual interface with the lower level mdns, and
 * produces the dns response back.
 *
 * The rewriting is done based on configuration initialized by calling
 * d2m_add_interface call.
 */

/*
 * These two calls are used to start/stop underlying mdns processing
 * of a request.
 */
void d2m_req_start(ohp_request req);
void d2m_req_stop(ohp_request req);

/*
 * Add one real system interface, with specified domain (reverse
 * happens automatically) to the request processing logic.
 */
void d2m_add_interface(const char *ifname, const char *domain);


/* This function should be provided by a client. */
void d2m_req_send(ohp_request req);

/* Add query (if it does not already exist). */
struct ohp_query *d2m_req_add_query(ohp_request req, const char *query, uint16_t qtype);

void d2m_req_free(ohp_request req);

#endif /* DNS2MDNS_H */
