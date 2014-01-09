/*
 * $Id: dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:38:37 2014 mstenber
 * Last modified: Thu Jan  9 12:03:06 2014 mstenber
 * Edit time:     104 min
 *
 */

#include <stdlib.h>
#include <net/if.h>

#include "dns2mdns.h"
#include "ohybridproxy.h"
#include "dns_util.h"

typedef struct d2m_interface_struct {
  struct list_head head;

  /* Domain assigned to the interface. */
  char domain[kDNSServiceMaxDomainName];

  /* Actual interface - name + index. */
  char ifname[IFNAMSIZ];
  uint32_t ifindex;
} *d2m_interface;

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static DNSServiceRef conn = NULL;

static void _query_start(struct ohp_query *q);
static void _query_stop(struct ohp_query *q);

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
      L_DEBUG("DNSServiceCreateConnection succeeded; now have connection");
    }
  return conn;
}

static bool
_string_endswith(const char *s, const char *end)
{
  int l1 = strlen(s);
  int l2 = strlen(end);

  if (l1 < l2)
    return false;
  return strcmp(s + (l1 - l2), end) == 0;
}



static void
_service_callback(DNSServiceRef service __unused,
                  DNSServiceFlags flags,
                  uint32_t ifindex,
                  DNSServiceErrorType error,
                  const char *name,
                  uint16_t rrtype,
                  uint16_t rrclass,
                  uint16_t rdlen,
                  const void *rdata,
                  uint32_t ttl,
             void *context)
{
  ohp_query q = context;
  ohp_query nq;
  ohp_rr rr;
  bool probably_cf = false;

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
  if (rrclass != kDNSServiceClass_IN)
    {
      L_INFO("ignoring weird service class %d", rrclass);
      return;
    }
  /*
   * Specify interface for the whole request if it is not set yet.
   */
  if (!q->request->interface)
    {
      d2m_interface ip;

      list_for_each_entry(ip, &interfaces, head)
        {
          if (ip->ifindex == ifindex)
            {
              q->request->interface = ip;
              break;
            }
        }
      if (!q->request->interface)
        {
          L_INFO("ignoring from unconfigured interface#%d for %s/%d",
                 ifindex, name, rrtype);
          return;
        }
    }
  /*
   * Start nested queries if any. RFC6763 suggests that PTR records
   * should include pointed SRV/TXT records, and SRV records should
   * include pointed A/AAAA records (in recursive way).
   *
   * This may result in a large number of total queries. Hopefully
   * dns_sd is up to it.
   */
  switch (rrtype)
    {
    case kDNSServiceType_PTR:
      {
        char buf[kDNSServiceMaxDomainName];
        /* The relevant name is the only content of ptr. */
        if (ll2escaped(rdata, rdlen, buf, sizeof(buf))<0)
          {
            L_ERR("error decoding ptr record");
            return;
          }
        if ((nq = d2m_req_add_query(q->request, buf, kDNSServiceType_SRV)))
          _query_start(nq);
        if ((nq = d2m_req_add_query(q->request, buf, kDNSServiceType_TXT)))
          _query_start(nq);
      }
      /* Inverse PTRs are typically unique. */
      if (_string_endswith(name, ".arpa."))
        probably_cf = true;
      break;
    case kDNSServiceType_SRV:
      {
        char buf[kDNSServiceMaxDomainName];
        /* SRV record has 6 byte header + then name we're interested in. */
        /* The relevant name is the only content of ptr. */
        if (ll2escaped(rdata + 6, rdlen - 6, buf, sizeof(buf))<0)
          {
            L_ERR("error decoding ptr record");
            return;
          }
        if ((nq = d2m_req_add_query(q->request, buf, kDNSServiceType_A)))
          _query_start(nq);
        if ((nq = d2m_req_add_query(q->request, buf, kDNSServiceType_AAAA)))
          _query_start(nq);
      }
      probably_cf = true;
      break;
    case kDNSServiceType_A:
    case kDNSServiceType_AAAA:
      probably_cf = true;
      break;
    }
  if (ttl > MAXIMUM_MDNS_TO_DNS_TTL)
    ttl = MAXIMUM_MDNS_TO_DNS_TTL;
  L_DEBUG("adding rr %s/%d (%d bytes, %d ttl)",
          name, rrtype, rdlen, ttl);
  rr = calloc(1, sizeof(*rr) + rdlen);
  if (!rr)
    return;
  list_add(&rr->head, &q->rrs);
  /* XXX - actually store the result somewhere and rewrite them. */
  if (probably_cf)
    {
      _query_stop(q);
    }
}

static void _query_start(ohp_query q)
{
  int flags = kDNSServiceFlagsShareConnection;
  int ifindex;
  int err;
  d2m_interface ifo = NULL, ip;

  /*
   * First off, if the _request_ is already bound to an interface, we
   * can use that.
   */
  if (!(ifo = q->request->interface))
    {
      /*
       * Look at the request. Either it ends with one of the domains we
       * already have, or it ends with arpa, or we ignore it.
       */
      if (_string_endswith(q->query, ".arpa."))
        {
          ifo = NULL;
        }
      else
        {
          list_for_each_entry(ip, &interfaces, head)
            {
              if (_string_endswith(q->query, ip->domain))
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
    }
  ifindex = ifo ? ifo->ifindex : 0;
  q->service = _get_conn();
  INIT_LIST_HEAD(&q->rrs);
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
  q->request->running++;
}

static void _req_send(ohp_request req)
{
  if (req->sent)
    return;
  req->sent = true;
  L_DEBUG("calling d2m_req_send for %p", req);
  d2m_req_send(req);
}

static void _query_stop(ohp_query q)
{
  if (q->service)
    {
      DNSServiceRefDeallocate(q->service);
      q->service = NULL;
      if (!(--(q->request->running)))
        {
          _req_send(q->request);
        }
    }
}

static void _request_timeout(struct uloop_timeout *t)
{
  ohp_request req = container_of(t, struct ohp_request, timeout);

  /* Just call stop, it will call send eventually if it already hasn't. */
  L_DEBUG("_request_timeout");
  d2m_req_stop(req);
}

void d2m_req_start(ohp_request req)
{
  ohp_query q;

  L_DEBUG("d2m_req_start %p", req);
  list_for_each_entry(q, &req->queries, head)
    {
      _query_start(q);
    }
  req->timeout.cb = _request_timeout;
  uloop_timeout_set(&req->timeout, MAXIMUM_REQUEST_DURATION_IN_MS);
}

void d2m_req_stop(ohp_request req)
{
  ohp_query q;

  L_DEBUG("d2m_req_stop %p", req);

  /* Cancel the timeout if we already didn't fire it. */
  uloop_timeout_cancel(&req->timeout);

  /* Stop the sub-queries. */
  list_for_each_entry(q, &req->queries, head)
    _query_stop(q);
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
  list_add(&ifo->head, &interfaces);
  L_DEBUG("d2m_add_interface if:%s/%d domain:%s", ifname, ifo->ifindex, domain);
}


ohp_query
d2m_req_add_query(ohp_request req, char *query, uint16_t qtype)
{
  ohp_query q;

  /* Determine if it's uninitialized. */
  L_DEBUG("adding query %s/%d to %p", query, qtype, req);
  if (!req->queries.next)
    {
      INIT_LIST_HEAD(&req->queries);
    }
  list_for_each_entry(q, &req->queries, head)
    {
      if (strcmp(q->query, query) == 0 && (q->qtype == qtype
                                           || q->qtype == kDNSServiceType_ANY))
        {
          L_DEBUG(" .. but it already exists");
          return NULL;
        }
    }
  q = calloc(1, sizeof(*q));
  if (!q) abort();
  q->query = strdup(query);
  if (!q->query) abort();
  q->qtype = qtype;
  q->request = req;
  list_add_tail(&q->head, &req->queries);
  return q;
}

static void _rr_free(ohp_rr rr)
{
  list_del(&rr->head);
  free(rr);
}

static void _query_free(ohp_query q)
{
  list_del(&q->head);
  while (!list_empty(&q->rrs))
    _rr_free(list_first_entry(&q->rrs, struct ohp_rr, head));
  free(q);
}

static void _req_free(ohp_request req)
{
  if (req->head.next)
    list_del(&req->head);
  /* Free shouldn't trigger send. */
  req->sent = true;
  /* Stop sub-queries. */
  d2m_req_stop(req);
  /* Free contents. */
  while (!list_empty(&req->queries))
    _query_free(list_first_entry(&req->queries, struct ohp_query, head));
}

void d2m_req_free(ohp_request req)
{
  _req_free(req);
  free(req);
}
