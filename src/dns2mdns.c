/*
 * $Id: dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:38:37 2014 mstenber
 * Last modified: Sat Sep 12 21:36:45 2015 mstenber
 * Edit time:     108 min
 *
 */

#include <stdlib.h>
#include <net/if.h>

#include "dns2mdns_i.h"
#include "io.h"
#include "dns_proto.h"
#include "dns_util.h"
#include "cache.h"

#define LOCAL_SUFFIX "local."

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);

static void _conn_free(d2m_conn c)
{
  if (!c)
    return;
  if (c->fd.cb)
    uloop_fd_delete(&c->fd);
  if (c->service)
    {
      /* This macro may be apparently NOP too? */
      DNSServiceRefDeallocate(c->service);
    }
  free(c);
}

static void
_fd_callback(struct uloop_fd *u, unsigned int events __unused)
{
  d2m_conn c = container_of(u, struct d2m_conn_struct, fd);
  int r;

  if (!u->error && !u->eof)
    {
      if ((r = DNSServiceProcessResult(c->service)) == kDNSServiceErr_NoError)
        return;
      L_ERR("error %d in _fd_callback", r);
    }
  else if (u->eof)
    {
      L_ERR("eof from mdnsd socket");
    }
  else
    {
      L_ERR("error from mdnsd socket");
    }
  io_reset();
}

static void _conn_register(d2m_conn conn)
{
  conn->fd.fd = DNSServiceRefSockFD(conn->service);
  if (conn->fd.fd)
    {
      conn->fd.cb = _fd_callback;
      (void)uloop_fd_add(&conn->fd, ULOOP_READ);
    }
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

static cache_rr
_query_add_rr(ohp_query q, const char *name, dns_rr drr, const void *rdata)
{
  const char *rrname;
  ohp_request req = q->io->request->b_private;

  if (q->use_query_name_in_reply)
    rrname = q->io->query;
  else
    {
      ohp_request req = q->io->request->b_private;
      rrname = TO_DNS(req->interface, name);
    }

  if (!rrname)
    return NULL;
  int slen = drr->rdlen;
  uint8_t tbuf[kDNSServiceMaxDomainName+8], *p = tbuf, *eom = tbuf + kDNSServiceMaxDomainName + 8;
  switch (drr->rrtype)
    {
    case kDNSServiceType_SRV:
      {
        int srvlen = sizeof(struct dns_rdata_srv);
        if (slen < srvlen)
          return NULL;
        memcpy(tbuf, rdata, srvlen);
        rdata += srvlen;
        p += srvlen;
        slen -= srvlen;
      }
    case kDNSServiceType_PTR:
      {
        char dbuf[kDNSServiceMaxDomainName];
        int r;

        /* The relevant name is the only content of ptr. */
        if ((r = ll2escaped(NULL, rdata, slen, dbuf, sizeof(dbuf)))<0)
          {
            L_ERR("error decoding %d byte ptr(/srv) record: %d", slen, r);
            return NULL;
          }
        const char *qb = TO_DNS(req->interface, dbuf);
        r = escaped2ll(qb, p, eom - p);
        if (r < 0)
          {
            L_ERR("error encoding ptr(/srv) record");
            return NULL;
          }
        p += r;
      }
      rdata = tbuf;
      drr->rdlen = p - tbuf;
      break;
    default:
      break;
    }
  return rrlist_add_rr(q->initial ? &q->io->request->e->an
                       : &q->io->request->e->ar,
                       rrname, drr, rdata);
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
  ohp_request req = q->io->request->b_private;
  io_query nq;
  bool probably_cf = false;
  const uint8_t *rbytes = rdata;

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
  if (!req->interface)
    {
      d2m_interface ip;

      list_for_each_entry(ip, &interfaces, head)
        {
          if (ip->ifindex == ifindex || !ifindex)
            {
              req->interface = ip;
              break;
            }
        }
      if (!req->interface)
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
      /* Inverse PTRs are typically unique (and lack SRV/TXT of interest). */
      if (_string_endswith(name, ".arpa."))
        probably_cf = true;
      else
        {
          char buf[kDNSServiceMaxDomainName];

          /* The relevant name is the only content of ptr. */
          if (ll2escaped(NULL, rdata, rdlen, buf, sizeof(buf))<0)
            {
              L_ERR("error decoding ptr record");
              return;
            }
          const char *qb = TO_DNS(req->interface, buf);
          if (!qb)
            return;
          if ((nq = io_req_add_query_t(req->io, qb, kDNSServiceType_SRV)))
            io_query_start(nq);
          if ((nq = io_req_add_query_t(req->io, qb, kDNSServiceType_TXT)))
            io_query_start(nq);
        }
      break;
    case kDNSServiceType_SRV:
      {
        char buf[kDNSServiceMaxDomainName];
        /* The relevant name is the only content of ptr. */
        int srv_header_size = sizeof(struct dns_rdata_srv);
        if (ll2escaped(NULL, rdata + srv_header_size, rdlen - srv_header_size,
                       buf, sizeof(buf))<0)
          {
            L_ERR("error decoding ptr record");
            return;
          }
        const char *qb = TO_DNS(req->interface, buf);
        if (!qb)
            return;
        if ((nq = io_req_add_query_t(req->io, qb, kDNSServiceType_AAAA)))
          io_query_start(nq);
        if ((nq = io_req_add_query_t(req->io, qb, kDNSServiceType_A)))
          io_query_start(nq);
      }
      probably_cf = true;
      break;
    case kDNSServiceType_A:
      if (rdlen != 4 || (rbytes[0] == 169 && rbytes[1] == 254))
          return;
      probably_cf = true;
      break;

    case kDNSServiceType_AAAA:
      if (rdlen != 16 || (rbytes[0] == 0xfe && (rbytes[1] & 0xc0) == 0x80))
          return;
      probably_cf = true;
      break;
    }
  if (ttl > MAXIMUM_MDNS_TO_DNS_TTL)
    ttl = MAXIMUM_MDNS_TO_DNS_TTL;
  L_DEBUG("adding rr %s/%d (%d bytes, %d ttl)",
          q->io->query, rrtype, rdlen, ttl);
  struct dns_rr drr;
  drr.rrtype = rrtype;
  drr.rrclass = rrclass;
  drr.rdlen = rdlen;
  drr.ttl = ttl;
  /* If add succeeds, and is probably cf, we can perhaps stop the query. */
  if (_query_add_rr(q, name, &drr, rdata) && probably_cf
      && !(flags & kDNSServiceFlagsMoreComing))
    io_query_stop(q->io);
}

ohp_query _query_get(io_query ioq)
{
  if (ioq->b_private)
    return ioq->b_private;
  ohp_query q = calloc(1, sizeof(*q));
  ioq->b_private = q;
  q->io = ioq;
  return q;
}

bool b_query_start(io_query ioq)
{
  int flags = kDNSServiceFlagsForceMulticast;
  int ifindex;
  int err;
  d2m_interface ifo = NULL, ip;
  const char *qb = ioq->query;
  ohp_request req = ioq->request->b_private;
  ohp_query q = _query_get(ioq);

  /*
   * First off, if the _request_ is already bound to an interface, we
   * can use that.
   */
  if (!(ifo = req->interface))
    {
      /*
       * Look at the request. Either it ends with one of the domains we
       * already have, or it ends with arpa, or we ignore it.
       */
      if (_string_endswith(qb, ".arpa."))
        {
          ifo = NULL;
          q->use_query_name_in_reply = true;
        }
      else
        {
          list_for_each_entry(ip, &interfaces, head)
            {
              if (_string_endswith(qb, ip->domain))
                {
                  ifo = ip;
                  break;
                }
            }

          if (!ifo)
            {
              L_INFO("impossible to serve query:%s", qb);
              goto done;
            }

          req->interface = ifo;
        }
    }
  if (ifo)
    qb = TO_MDNS(ifo, qb);
  ifindex = ifo ? ifo->ifindex : 0;
  q->conn = calloc(1, sizeof(*q->conn));
  if (!q->conn)
    goto done;
  L_DEBUG("DNSServiceQueryRecord %s @ %d", qb, ifindex);
  if ((err = DNSServiceQueryRecord(&q->conn->service, flags, ifindex,
                                   qb,
                                   ioq->dq.qtype,
                                   ioq->dq.qclass,
                                   _service_callback,
                                   q) != kDNSServiceErr_NoError))
    {
      L_ERR("Error %d initializing DNSServiceQueryRecord", err);
      goto done;
    }
  _conn_register(q->conn);
  return true;
 done:
  return false;
}

void b_query_stop(io_query ioq)
{
  ohp_query q = ioq->b_private;

  _conn_free(q->conn);
  q->conn = NULL;
}

void b_query_free(io_query ioq)
{
  ohp_query q = ioq->b_private;

  free(q);
}

static bool _add_interface(const char *ifname, uint32_t ifindex,
                           const char *domain)
{
  d2m_interface ifo;
    /* Normalize the domain by encoding it to ll and back. */
  uint8_t buf[kDNSServiceMaxDomainName];
  int r;

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
      return false;
    }
  L_DEBUG(" escaped2ll = %d", r);
  if ((r = ll2escaped(NULL, buf, r, ifo->domain, kDNSServiceMaxDomainName)) < 0)
    {
      L_ERR("ll2escaped failed for %s", domain);
      return false;
    }
  L_DEBUG(" ll2escaped= %d", r);
  strcpy(ifo->ifname, ifname);
  ifo->ifindex = ifindex;
  ifo->to_dns_delta = strlen(ifo->domain) - strlen(LOCAL_SUFFIX);
  list_add(&ifo->head, &interfaces);
  L_DEBUG("d2m_add_interface if:%s/%d domain:%s (from %s)", ifname, ifo->ifindex, ifo->domain, domain);
  return true;
}

bool d2m_add_interface(const char *ifname, const char *domain)
{
  uint32_t ifindex = if_nametoindex(ifname);

  if (!ifindex)
    {
      L_ERR("invalid interface:%s", ifname);
      return false;
    }
  return _add_interface(ifname, ifindex, domain);
}


void b_req_init(io_request ioreq)
{
  ohp_request req = calloc(1, sizeof(*req));

  ioreq->b_private = req;
  req->io = ioreq;
}

void b_req_free(io_request ioreq)
{
  ohp_request req = ioreq->b_private;

  /* Free private data itself */
  free(req);
}


void b_req_set_query(io_request req, const char *query, dns_query dq)
{
  io_query ioq = io_req_add_query(req, query, dq);
  ohp_query q = _query_get(ioq);

  q->initial = true;
}
