/*
 * $Id: dns2mdns_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:23:19 2014 mstenber
 * Last modified: Sat Sep 12 10:36:42 2015 mstenber
 * Edit time:     1 min
 *
 */

#pragma once

#include "dns2mdns.h"
#include "util.h"
#include "io.h"

#include <libubox/list.h>
#include <dns_sd.h>

/* If mdns claims TTL longer than this, we provide smaller one anyway,
 * as there's no invalidation mechanism available. */
#define MAXIMUM_MDNS_TO_DNS_TTL 120

typedef struct ohp_query {
  /* Backpointer to the io structure we are in */
  struct io_query *io;

  /* Replace DNS reply names with original query name (relevant with .arpa.) */
  bool use_query_name_in_reply;

  /* Pointer to the connection we are using (encapsulates also service
   * handle; may have 1:1 relationship to connections, or not). */
  struct d2m_conn_struct *conn;
} *ohp_query;


/* Private dns2mdns request structure (within io_request->b_private). */
typedef struct ohp_request {
  /* Backpointer to the io structure we are in */
  struct io_request *io;

  /* Used interface (if any; reverse queries we do on all interfaces
   * and do mapping based on result. the first result 'glues' the
   * interface, though) */
  struct d2m_interface_struct *interface;
} *ohp_request;

typedef struct d2m_interface_struct {
  struct list_head head;

  /* how much less (or more) space we need */
  int to_dns_delta;

  /* Domain assigned to the interface. */
  char domain[kDNSServiceMaxDomainName];

  /* Actual interface - name + index. */
  char ifname[IFNAMSIZ];
  uint32_t ifindex;
} *d2m_interface;

typedef struct d2m_conn_struct {
  DNSServiceRef service;
  struct uloop_fd fd;
} *d2m_conn;
