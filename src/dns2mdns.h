/*
 * $Id: dns2mdns.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:23:19 2014 mstenber
 * Last modified: Thu Feb 20 13:25:32 2014 mstenber
 * Edit time:     46 min
 *
 */

#ifndef DNS2MDNS_H
#define DNS2MDNS_H

#include <libubox/list.h>
#include <libubox/uloop.h>

#ifdef USE_MDNSRESPONDER
#include <dns_sd.h>
#endif

#include "dns_proto.h"

/* If mdns claims TTL longer than this, we provide smaller one anyway,
 * as there's no invalidation mechanism available. */
#define MAXIMUM_MDNS_TO_DNS_TTL 120

/* How many milliseconds can we wait for results until we're done?
 * MDNS operates on sub-second speed, and some DNS clients starts
 * resending at second. Sigh. */
#define MAXIMUM_REQUEST_DURATION_IN_MS 500

/* Maximum domain name */
#define MAXIMUM_DOMAIN_NAME 1024

/* DNS constants */
#define DNS_CLASS_IN	1

enum {
	DNS_TYPE_A = 1,
	DNS_TYPE_PTR = 12,
	DNS_TYPE_TXT = 16,
	DNS_TYPE_AAAA = 28,
	DNS_TYPE_SRV = 33,
	DNS_TYPE_ANY = 255,
};


typedef struct ohp_rr {
  struct list_head head;

  char *name;
  struct dns_rr drr;
} *ohp_rr;

typedef struct ohp_query {
  struct list_head head;

  /*
   * This is the DNS-SD version, not MDNS version of query. Conversion
   * between DNS and MDNS happens on the go.
   */
  char *query;
  struct dns_query dq;

  /* Replace DNS reply names with original query name (relevant with .arpa.) */
  bool use_query_name_in_reply;

  /* Pointer to the connection we are using (encapsulates also service
   * handle; may have 1:1 relationship to connections, or not). */
  struct d2m_conn_struct *conn;

  /* Backpointer to the request we are in. */
  struct ohp_request *request;

  /* The results of the particular (sub-)query. */
  struct list_head rrs;
} *ohp_query;


/* Shared structure between this + main ohp loop. */
typedef struct ohp_request {
  /* List head for dns2mdns.c; a list of _active_ requests (start
   * called, but not yet stop) is kept there. */
  struct list_head lh;

  /* Active timeout if any. */
  struct uloop_timeout timeout;

  /* Information from the DNS request by client. */
  uint16_t dnsid;
  size_t maxlen;
  bool udp;
  bool active;

  /* List of sub-queries. The first query is the 'main' one, and the
   * rest 'additional records' ones. */
  struct list_head queries;

  /* Number of running queries. */
  int running;

  /* Is it started at all? */
  bool started;

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
int d2m_add_interface(const char *ifname, const char *domain);


/*
 * Prepare dns2mdns engine
 */
void d2m_start(void);


/* Add query (if it does not already exist). */
struct ohp_query *d2m_req_add_query(ohp_request req, const char *query, uint16_t qtype);

/* Produce reply to the pre-allocated buffer. Return value is the
 * number of bytes used, or -1 if the reply buffer is too small. */
int d2m_produce_reply(ohp_request req, uint8_t *buf, int buf_len);

void d2m_req_free(ohp_request req);

#endif /* DNS2MDNS_H */
