/*
 * $Id: dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:38:37 2014 mstenber
 * Last modified: Thu Jan  9 22:47:21 2014 mstenber
 * Edit time:     229 min
 *
 */

#include <stdlib.h>
#include <net/if.h>

#include "dns2mdns.h"
#include "ohybridproxy.h"
#include "dns_proto.h"
#include "dns_util.h"

#define LOCAL_SUFFIX "local."

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

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static DNSServiceRef conn = NULL;

static void _query_start(struct ohp_query *q);
static void _query_stop(struct ohp_query *q);
static void _req_send(ohp_request req);

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

const char *
_rewrite_domain(const char *src, char *buf, int buf_len,
                const char *src_domain,
                const char *dst_domain)
{
  int l = strlen(src);
  int l1 = strlen(src_domain);
  int l2 = strlen(dst_domain);
  int nl = l + l2 - l1 + 1;

  L_DEBUG("_rewrite_domain '%s'->%d bytes (%s->%s)",
          src, buf_len, src_domain, dst_domain);
  if (l < l1)
    {
      L_DEBUG("too short src for rewrite:%s", src);
      return NULL;
    }
  if (strcmp(src + (l - l1), src_domain))
    {
      L_INFO("src domain mismatch: %s not in %s", src, src_domain);
      return NULL;
    }
  if (buf_len < nl)
    {
      L_ERR("too short buffer in _rewrite_domain");
      return NULL;
    }
  memcpy(buf, src, l - l1);
  strcpy(buf + l - l1, dst_domain);
  L_DEBUG("rewrote -> '%s'", buf);
  return buf;
}

#define TO_DNS(ifo, n)                                                  \
(ifo ? _rewrite_domain(n,                                               \
                       alloca(strlen(n) + 1 + ifo->to_dns_delta),       \
                       strlen(n) + 1 + ifo->to_dns_delta,               \
                       LOCAL_SUFFIX,                                    \
                       ifo->domain)                                     \
 : NULL)

#define TO_MDNS(ifo, n)                                                 \
(ifo ? _rewrite_domain(n,                                               \
                       alloca(strlen(n) + 1 - ifo->to_dns_delta),       \
                       strlen(n) + 1 - ifo->to_dns_delta,               \
                       ifo->domain, LOCAL_SUFFIX                        \
                       )                                                \
 : NULL)

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
        const char *qb = TO_DNS(q->request->interface, buf);
        if (!qb)
            return;
        if ((nq = d2m_req_add_query(q->request, qb, kDNSServiceType_SRV)))
          _query_start(nq);
        if ((nq = d2m_req_add_query(q->request, qb, kDNSServiceType_TXT)))
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
        const char *qb = TO_DNS(q->request->interface, buf);
        if (!qb)
            return;
        if ((nq = d2m_req_add_query(q->request, qb, kDNSServiceType_A)))
          _query_start(nq);
        if ((nq = d2m_req_add_query(q->request, qb, kDNSServiceType_AAAA)))
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
          q->query, rrtype, rdlen, ttl);
  rr = calloc(1, sizeof(*rr) + rdlen);
  if (!rr)
    return;
  const char *rrname = TO_DNS(q->request->interface, name);
  if (rrname)
	  rr->name = strdup(rrname);
  if (!rr->name)
    {
      free(rr);
      return;
    }
  rr->drr.rrtype = rrtype;
  rr->drr.rdlen = rdlen;
  rr->drr.ttl = ttl;
  memcpy(rr->drr.rdata, rdata, rdlen);
  list_add(&rr->head, &q->rrs);
  if (probably_cf)
    _query_stop(q);
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
              if (!q->request->running)
                _req_send(q->request);
              return;
            }

          q->request->interface = ifo;
        }
    }
  ifindex = ifo ? ifo->ifindex : 0;
  q->service = _get_conn();
  const char *qb = q->query;
  if (ifo)
    qb = TO_MDNS(ifo, q->query);
  L_DEBUG("DNSServiceQueryRecord %s @ %d", qb, ifindex);
  if ((err = DNSServiceQueryRecord(&q->service, flags, ifindex,
                                   qb,
                                   q->dq.qtype,
                                   q->dq.qclass,
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
  ohp_send_reply(req);
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

int d2m_add_interface(const char *ifname, const char *domain)
{
  d2m_interface ifo;
    /* Normalize the domain by encoding it to ll and back. */
  uint8_t buf[kDNSServiceMaxDomainName];
  int r;
  uint32_t ifindex = if_nametoindex(ifname);

  if (!ifindex)
    {
      return -1;
    }
  ifo = calloc(1, sizeof(*ifo));
  if (!ifo)
    {
      L_ERR("calloc failure");
      return -1;
    }
  if ((r = escaped2ll(domain, buf, sizeof(buf))) < 0)
    {
      L_ERR("escaped2ll failed for %s", domain);
      free(ifo);
      return -1;
    }
  L_DEBUG(" escaped2ll = %d", r);
  if ((r = ll2escaped(buf, r, ifo->domain, kDNSServiceMaxDomainName)) < 0)
    {
      L_ERR("ll2escaped failed for %s", domain);
      return -1;
    }
  L_DEBUG(" ll2escaped= %d", r);
  strcpy(ifo->ifname, ifname);
  ifo->ifindex = ifindex;
  ifo->to_dns_delta = strlen(ifo->domain) - strlen(LOCAL_SUFFIX);
  list_add(&ifo->head, &interfaces);
  L_DEBUG("d2m_add_interface if:%s/%d domain:%s (from %s)", ifname, ifo->ifindex, ifo->domain, domain);
  return 0;
}


ohp_query
d2m_req_add_query(ohp_request req, const char *query, uint16_t qtype)
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
      uint16_t oqtype = q->dq.qtype;
      if (strcmp(q->query, query) == 0
          && (oqtype == qtype
              || oqtype == kDNSServiceType_ANY))
        {
          L_DEBUG(" .. but it already exists");
          return NULL;
        }
    }
  q = calloc(1, sizeof(*q));
  if (!q) abort();
  q->query = strdup(query);
  if (!q->query) abort();
  q->dq.qtype = qtype;
  q->dq.qclass = kDNSServiceClass_IN;
  q->request = req;
  INIT_LIST_HEAD(&q->rrs);
  list_add_tail(&q->head, &req->queries);
  return q;
}

static void _rr_free(ohp_rr rr)
{
  free(rr->name);
  list_del(&rr->head);
  free(rr);
}

static void _query_free(ohp_query q)
{
  list_del(&q->head);
  while (!list_empty(&q->rrs))
    _rr_free(list_first_entry(&q->rrs, struct ohp_rr, head));
  free(q->query);
  free(q);
}

void d2m_req_free(ohp_request req)
{
  /* Free shouldn't trigger send. */
  req->sent = true;
  /* Stop sub-queries. */
  d2m_req_stop(req);
  /* Free contents. */
  while (!list_empty(&req->queries))
    _query_free(list_first_entry(&req->queries, struct ohp_query, head));
}

#define PUSH_RAW(s, len)                                        \
do {                                                            \
  buf_len -= len;                                               \
  if (buf_len < 0) {                                            \
    L_DEBUG("unable to push %d byte structure (just %d left)",  \
            (int)len, buf_len);                                 \
    return -1;                                                  \
  }                                                             \
  s = (void *)buf;                                              \
  buf += len;                                                   \
 } while(0)

#define PUSH(s) PUSH_RAW(s, sizeof(*s))

#define TO_BE16(s)              \
do {                            \
  if (real)                     \
    {                           \
      uint16_t *i = (void *)s;  \
      void *e = i;              \
      e += sizeof(*s);          \
      while (i != e)            \
        {                       \
          *i = cpu_to_be16(*i); \
          i++;                  \
        }                       \
    }                           \
} while(0)

#define PUSH_EXPANDED(e)                        \
do {                                            \
  uint8_t _buf[256];                            \
  int _r = escaped2ll(e, _buf, sizeof(_buf));   \
  uint8_t *dst;                                 \
  if (_r <=0 ) {                                \
    return -1;                                  \
  }                                             \
  PUSH_RAW(dst, _r);                            \
  if (real)                                     \
    memcpy(dst, _buf, _r);                      \
 } while(0)

static int _push_rr(ohp_rr rr,
                    uint8_t *buf, int buf_len,
                    bool real)
{
  /* By default: We just push the data as is. */
  uint8_t *b;
  int len = rr->drr.rdlen;

  PUSH_RAW(b, len);
  if (real)
    memcpy(b, rr->drr.rdata, len);
  /* XXX - rewrite PTR, SRV (and perhaps also TXT). */
  return len;
}

static int _produce_reply(ohp_request req,
                          uint8_t *buf, int buf_len,
                          bool include_additional,
                          bool real)
{
  uint8_t *obuf = buf;
  ohp_query q;
  ohp_rr rr;
  bool first = true;
  dns_msg msg;
  dns_query dq;
  dns_rr dr;
  int r;

  /* XXX - should probably rewrite this to use name compression at
   * some point. for the time being, just using dns_util's raw
   * functions. */
  PUSH(msg);
  if (real)
    {
      memset(msg, 0, sizeof(*msg));
    }
  list_for_each_entry(q, &req->queries, head)
    {
      if (first)
        {
          /* Push the query first. */
          PUSH_EXPANDED(q->query);
          PUSH(dq);
          if (real)
            {
              msg->qdcount = 1;
              *dq = q->dq;
              TO_BE16(dq);
            }
        }
      list_for_each_entry(rr, &q->rrs, head)
        {
          PUSH_EXPANDED(rr->name);
          PUSH(dr);
          r = _push_rr(rr, buf, buf_len, real);
          if (r < 0)
            return r;
          buf += r;
          buf_len -= r;
          if (real)
            {
              *dr = rr->drr;
              if (first)
                msg->ancount++;
              else
                msg->arcount++;
              TO_BE16(dr);
              dr->ttl = cpu_to_be32(rr->drr.ttl);
            }
        }

      first = false;
      if (!include_additional)
        break;
    }
  if (first)
    {
      L_ERR("no query in d2m_produce_reply");
      return -1;
    }
  if (real)
    {
      msg->id = req->dnsid;
      msg->h = DNS_H_QR | DNS_H_AA;
      /* XXX - should we copy RD from original message like Lua code does?
       * why does it do that? hmm. */
    }
  TO_BE16(msg);
  return buf - obuf;
}

int d2m_produce_reply(ohp_request req, uint8_t *buf, int buf_len)
{
  /* There's 3 different types of responses. */
  /* 1) everything */
  /* 2) answer-only */
  /* 3) 'sorry, can't be arsed (partial answer) */
  int l;

  /* 1) */
  l = _produce_reply(req, NULL, buf_len, true, false);
  if (l >= 0)
    return _produce_reply(req, buf, buf_len, true, true);

  /* 2) */
  l = _produce_reply(req, NULL, buf_len, false, false);
  if (l >= 0)
    return _produce_reply(req, buf, buf_len, false, true);

  /* 3) (XXX) */
  uint8_t *obuf = buf;
  dns_msg msg;
  bool real = true;

  PUSH(msg);
  msg->id = req->dnsid;
  msg->h = DNS_H_QR | DNS_H_TC | DNS_H_AA;
  /* XXX - should we copy RD from original message like Lua code does?
   * why does it do that? hmm. */
  TO_BE16(msg);
  return buf - obuf;
}
