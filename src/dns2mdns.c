/*
 * $Id: dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:38:37 2014 mstenber
 * Last modified: Wed Jan  8 20:25:22 2014 mstenber
 * Edit time:     50 min
 *
 */

#include <stdlib.h>
#include <net/if.h>

#include "dns2mdns.h"
#include "ohybridproxy.h"
#include "dns_util.h"

typedef struct d2m_interface_struct {
  struct list_head lh;

  /* Domain assigned to the interface. */
  char domain[kDNSServiceMaxDomainName];

  /* Actual interface - name + index. */
  char ifname[IFNAMSIZ];
  uint32_t ifindex;
} *d2m_interface;

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static DNSServiceRef conn = NULL;

static void
_fd_callback(struct uloop_fd *u __unused, unsigned int events __unused)
{
  int r;

  if ((r = DNSServiceProcessResult(conn)) != kDNSServiceErr_NoError)
    {
      L_ERR("error %d in _fd_callback", r);
    }
}

static struct uloop_fd conn_fd = { .cb = _fd_callback };


static DNSServiceRef _get_conn()
{
  if (!conn)
    {
      int error = DNSServiceCreateConnection(&conn);
      if (error)
        {
          L_ERR("error %d in get_conn", error);
          abort();
        }
      conn_fd.fd = DNSServiceRefSockFD(conn);
      if (uloop_fd_add(&conn_fd, ULOOP_READ) < 0)
        {
          L_ERR("Error in uloop_fd_add");
          abort();
        }
    }
  return conn;
}



static void
_service_callback(DNSServiceRef service __unused,
                  DNSServiceFlags flags,
                  uint32_t ifindex,
                  DNSServiceErrorType error,
                  const char *name __unused,
                  uint16_t rrtype,
                  uint16_t rrclass __unused,
                  uint16_t rdlen,
                  const void *rdata,
                  uint32_t ttl,
             void *context)
{
  struct ohp_query *q = context;

  if (error != kDNSServiceErr_NoError)
    {
      L_ERR("error %d from DNSServiceQueryRecord", error);
      return;
    }
  if (!(flags & kDNSServiceFlagsAdd))
    {
      L_INFO("non-add _service_callback ignored for now (no LLQ)");
      return;
    }
}

static bool
string_endswith(const char *s, const char *end)
{
  int l1 = strlen(s);
  int l2 = strlen(end);

  if (l1 < l2)
    return false;
  return strcmp(s + (l1 - l2), end) == 0;
}

void d2m_query_start(struct ohp_query *q)
{
  int flags = kDNSServiceFlagsShareConnection;
  int ifindex;
  int err;
  d2m_interface ifo = NULL, ip;

  /*
   * Look at the request. Either it ends with one of the domains we
   * already have, or it ends with arpa, or we ignore it.
   */
  if (string_endswith(q->query, ".arpa."))
    {
      ifindex = 0;
      ifo = NULL;
    }
  else
    {
      list_for_each_entry(ip, &interfaces, lh)
        {
          if (string_endswith(q->query, ip->domain))
            {
              ifo = ip;
              break;
            }
        }

      if (!ifo)
        {
          L_INFO("impossible to serve query:%s", q->query);
          return;
        }
    }
  ifindex = ifo ? ifo->ifindex : 0;
  if ((err = DNSServiceQueryRecord(&q->service, flags, ifindex,
                                   q->query,
                                   q->qtype,
                                   kDNSServiceClass_IN,
                                   _service_callback,
                                   q) != kDNSServiceErr_NoError))
    {
      L_ERR("Error %d initializing DNSServiceQueryRecord", err);
      abort();
    }
}

void d2m_query_stop(struct ohp_query *q)
{
  if (q->service)
    DNSServiceRefDeallocate(q->service);
}

void d2m_request_start(struct ohp_request *req)
{
  struct ohp_query *q;

  list_for_each_entry(q, &req->queries, head)
    d2m_query_start(q);
}

void d2m_request_stop(struct ohp_request *req)
{
  struct ohp_query *q;

  list_for_each_entry(q, &req->queries, head)
    d2m_query_stop(q);
}

void d2m_add_interface(const char *ifname, const char *domain)
{
  d2m_interface ifo = calloc(1, sizeof(*ifo));
  /* Normalize the domain by encoding it to ll and back. */
  uint8_t buf[kDNSServiceMaxDomainName];
  int r;

  if (!ifo)
    {
      L_ERR("calloc failure");
      abort();
    }
  if ((r = escaped2ll(domain, buf, sizeof(buf))) < 0)
    {
      L_ERR("escaped2ll failed for %s", domain);
      return;
    }
  if ((r = ll2escaped(buf, r, ifo->domain, kDNSServiceMaxDomainName)) < 0)
    {
      L_ERR("ll2escaped failed for %s", domain);
      return;
    }
  strcpy(ifo->ifname, ifname);
  ifo->ifindex = if_nametoindex(ifname);
  list_add(&ifo->lh, &interfaces);
}


struct ohp_query *
d2m_req_add_query(struct ohp_request *req, char *query, uint16_t qtype)
{
  struct ohp_query *q;

  list_for_each_entry(q, &req->queries, head)
    {
      if (strcmp(q->query, query) == 0 && q->qtype == qtype)
        return NULL;
    }
  q = calloc(1, sizeof(*q));
  if (!q) abort();
  q->query = strdup(query);
  if (!q->query) abort();
  q->qtype = qtype;
  list_add_tail(&q->head, &req->queries);
  return q;
}
