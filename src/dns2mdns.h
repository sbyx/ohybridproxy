/*
 * $Id: dns2mdns.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:23:19 2014 mstenber
 * Last modified: Wed Jan  8 18:03:56 2014 mstenber
 * Edit time:     9 min
 *
 */

#ifndef DNS2MDNS_H
#define DNS2MDNS_H

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <dns_sd.h>

/* Shared structure between this + main ohp loop. */
struct ohp_request {
  struct list_head head;
  struct uloop_timeout timeout;

  /* Information from the DNS request by client. */
  uint16_t dnsid;
  char *query;
  uint16_t qtype;
  size_t maxlen;
  bool udp;

  /* Pointer to the mDNSResponder client context (dns_sd.h) for the
   * query we are runnning, if any. */
  DNSServiceRef service;
  struct uloop_fd service_fd;

  /* Used interface (if any; reverse queries we do on all interfaces
   * and do mapping based on result) */
  struct d2m_interface_struct *interface;
};

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
void d2m_request_start(struct ohp_request *req);
void d2m_request_stop(struct ohp_request *req);

/*
 * Add one real system interface, with specified domain (reverse
 * happens automatically) to the request processing logic.
 */
void d2m_add_interface(const char *ifname, const char *domain);


/* This function should be provided by a client. */
void d2m_request_send(struct ohp_request *req, uint8_t *data, size_t data_len);

#endif /* DNS2MDNS_H */
