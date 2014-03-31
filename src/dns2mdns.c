/*
 * $Id: dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:38:37 2014 mstenber
 * Last modified: Mon Mar 31 13:29:49 2014 mstenber
 * Edit time:     432 min
 *
 */

#include <stdlib.h>
#include <net/if.h>

#include "dns2mdns.h"
#include "ohybridproxy.h"
#include "dns_proto.h"
#include "dns_util.h"

#define LOCAL_SUFFIX "local."

/* Hack which deals with some implementations publishing
 * linklocal-only addresses even if they really have globals. Use with
 * care. */
#undef ENABLE_HACK_GLOBALISH_TO_LINKLOCAL_REWRITE

static struct list_head active_ohp_requests = LIST_HEAD_INIT(active_ohp_requests);

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

typedef struct d2m_conn_struct {
  DNSServiceRef service;
  struct uloop_fd fd;
} *d2m_conn;

static int _query_start(struct ohp_query *q);
static int _query_stop(struct ohp_query *q);
static void _req_send(ohp_request req);

static void _conn_free(d2m_conn c)
{
  if (!c)
    return;
  if (c->fd.cb)
    uloop_fd_delete(&c->fd);
  if (c->service)
    DNSServiceRefDeallocate(c->service);
  free(c);
}

static void _state_reset()
{
  /* First off, clear the active requests */
  ohp_request r, nr;
  list_for_each_entry_safe(r, nr, &active_ohp_requests, lh)
    d2m_req_stop(r);
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
  _state_reset();
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

static ohp_rr
_query_add_rr(ohp_query q, const char *name, dns_rr drr, const void *rdata)
{
  const char *rrname;

  if (q->use_query_name_in_reply)
    rrname = q->query;
  else
    rrname = TO_DNS(q->request->interface, name);

  if (!rrname)
    return NULL;
  ohp_rr rr = calloc(1, sizeof(*rr) + drr->rdlen);
  if (!rr)
    return NULL;
  if (!(rr->name = strdup(rrname)))
    {
      free(rr);
      return NULL;
    }
  rr->drr = *drr;
  memcpy(rr->drr.rdata, rdata, drr->rdlen);
  list_add(&rr->head, &q->rrs);
  return rr;
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
  if (!q->request->interface)
    {
      d2m_interface ip;

      list_for_each_entry(ip, &interfaces, head)
        {
          if (ip->ifindex == ifindex || !ifindex)
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
      /* Inverse PTRs are typically unique (and lack SRV/TXT of interest). */
      if (_string_endswith(name, ".arpa."))
        probably_cf = true;
      else
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
      break;
    case kDNSServiceType_SRV:
      {
        char buf[kDNSServiceMaxDomainName];
        /* The relevant name is the only content of ptr. */
        int srv_header_size = sizeof(struct dns_rdata_srv);
        if (ll2escaped(rdata + srv_header_size, rdlen - srv_header_size,
                       buf, sizeof(buf))<0)
          {
            L_ERR("error decoding ptr record");
            return;
          }
        const char *qb = TO_DNS(q->request->interface, buf);
        if (!qb)
            return;
        if ((nq = d2m_req_add_query(q->request, qb, kDNSServiceType_AAAA)))
          _query_start(nq);
        if ((nq = d2m_req_add_query(q->request, qb, kDNSServiceType_A)))
          _query_start(nq);
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
          q->query, rrtype, rdlen, ttl);
  struct dns_rr drr;
  drr.rrtype = rrtype;
  drr.rrclass = rrclass;
  drr.rdlen = rdlen;
  drr.ttl = ttl;
  /* If add succeeds, and is probably cf, we can perhaps stop the query. */
  if (_query_add_rr(q, name, &drr, rdata) && probably_cf
      && !(flags & kDNSServiceFlagsMoreComing))
    _query_stop(q);
}

static int _query_start(ohp_query q)
{
  int flags = kDNSServiceFlagsForceMulticast;
  int ifindex;
  int err;
  d2m_interface ifo = NULL, ip;
  const char *qb = q->query;

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
#ifdef ENABLE_HACK_GLOBALISH_TO_LINKLOCAL_REWRITE
          /* Check if it's IPv6 address; if so, and it's for
           * non-linklocal address, we may have to rewrite it (This is
           * mainly thanks to mdnsresponder(?) bug in which globals
           * aren't advertised for the reverses even if
           * available. Sigh.). */
          struct in6_addr a;
          if (escaped2ipv6(qb, &a))
            {
              /* Ok, it _is_ IPv6 address. If it's ULA or GUA, convert
               * it to linklocal one. */
              if ((a.s6_addr[0] & 0x70) == 0x20
                  || ((a.s6_addr[0] & 0xfe) == 0xfc))
                {
                  char *c = alloca(DNS_MAX_ESCAPED_LEN);
                  int i;
                  if (c)
                    {
                      a.s6_addr[0] = 0xFE;
                      a.s6_addr[1] = 0x80;
                      for (i = 2 ; i < 8 ; i++)
                        a.s6_addr[i] = 0;
                      ipv62escaped(&a, c);
                      qb = c;
                    }
                }
              /* Reverse direction is done automatically, as we change
               * here only the arguments given to the DNS-SD library;
               * the PTR's rdata is just a name (that will be
               * rewritten appropriately). */
            }
#endif /* ENABLE_HACK_GLOBALISH_TO_LINKLOCAL_REWRITE */
          q->use_query_name_in_reply = true;
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
              goto done;
            }

          q->request->interface = ifo;
        }
    }
  if (ifo)
    qb = TO_MDNS(ifo, q->query);
  ifindex = ifo ? ifo->ifindex : 0;
  q->conn = calloc(1, sizeof(*q->conn));
  if (!q->conn)
    goto done;
  L_DEBUG("DNSServiceQueryRecord %s @ %d", qb, ifindex);
  if ((err = DNSServiceQueryRecord(&q->conn->service, flags, ifindex,
                                   qb,
                                   q->dq.qtype,
                                   q->dq.qclass,
                                   _service_callback,
                                   q) != kDNSServiceErr_NoError))
    {
      L_ERR("Error %d initializing DNSServiceQueryRecord", err);
      goto done;
    }
  _conn_register(q->conn);
  q->request->running++;
  return 0;
 done:
  if (!q->request->running)
    {
      _req_send(q->request);
      return 1;
    }
  return 0;
}

static void _req_send(ohp_request req)
{
  if (req->sent)
    return;
  req->sent = true;
  L_DEBUG("calling d2m_req_send for %p", req);
  ohp_send_reply(req);
}

static int _query_stop(ohp_query q)
{
  if (q->conn && q->conn->service)
    {
      DNSServiceRefDeallocate(q->conn->service);
      q->conn->service = NULL;
      if (!(--(q->request->running)))
        {
          _req_send(q->request);
          return -1;
        }
    }
  return 0;
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

  /* In case of instant failure, we don't want query-start triggered
   * code to have incomplete request structure -> we set things
   * here. */
  uloop_timeout_set(&req->timeout, MAXIMUM_REQUEST_DURATION_IN_MS);
  req->timeout.cb = _request_timeout;
  req->started = true;
  list_add(&req->lh, &active_ohp_requests);
  list_for_each_entry(q, &req->queries, head)
    {
      if (_query_start(q))
        return;
    }
}

void d2m_req_stop(ohp_request req)
{
  ohp_query q;

  L_DEBUG("d2m_req_stop %p", req);
  if (!req->started)
    return;
  req->started = false;
  list_del(&req->lh);

  /* Cancel the timeout if we already didn't fire it. */
  uloop_timeout_cancel(&req->timeout);

  /* Stop the sub-queries. */
  list_for_each_entry(q, &req->queries, head)
    if (_query_stop(q))
      return;
}

static int _add_interface(const char *ifname, uint32_t ifindex,
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

int d2m_add_interface(const char *ifname, const char *domain)
{
  uint32_t ifindex = if_nametoindex(ifname);

  if (!ifindex)
    {
      L_ERR("invalid interface:%s", ifname);
      return -1;
    }
  return _add_interface(ifname, ifindex, domain);
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
  if (!q)
    return NULL;
  q->query = strdup(query);
  if (!q->query)
    {
      free(q);
      return NULL;
    }
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
  _conn_free(q->conn);
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

static void _init_deduplicate(uint8_t *saved[], size_t saved_max, void *msghdr)
{
	memset(saved, 0, sizeof(*saved) * saved_max);
	if (saved_max > 0)
		saved[0] = msghdr;
}

static int _push_deduplicate(uint8_t *lbldata, int lbllen, uint8_t *target,
		uint8_t *saved[], size_t saved_max)
{
	uint8_t *eoc = &lbldata[lbllen-1];
	uint8_t **eos = &saved[saved_max];

	if (saved_max < 1 || lbllen < 2 || *eoc != 0)
		return lbllen;

	bool matching = true;
	size_t rewrite_offset = 0;
	uint8_t *rewrite_c = NULL;
	do {
		uint8_t *eol = &lbldata[lbllen];
		uint8_t *c = lbldata;
		for (;;) {
			if ((*c & 0xc0) || *c == 0 || &c[*c + 1] > eoc)
				return lbllen;

			if (&c[*c + 1] == eoc)
				break;

			c = &c[*c + 1];
		}



		uint8_t **s;
		for (s = &saved[1]; s < eos && *s; ++s) {
			size_t savelen = eol - c, j;
			for (j = 0; matching && j < savelen && (*s)[j] == c[j]; ++j);

			if (j == savelen) { // Match found
				size_t offset = *s - saved[0];
				if (offset <= 0x3fff) {
					rewrite_c = c;
					rewrite_offset = offset;
				}
				break;
			}
		}

		if (rewrite_c && (s >= eos || *s == NULL)) {
			rewrite_c[0] = 0xc0 | rewrite_offset >> 8;
			rewrite_c[1] = rewrite_offset & 0xff;
			lbllen = &rewrite_c[2] - lbldata;

			rewrite_c = NULL;
			continue;
		}

		if (s < eos && *s == NULL) {
			// otherwise save new label location if we still have space
			*s = &target[c - lbldata];
			matching = false;
		}

		eoc = c;
	} while (eoc != lbldata);

	if (rewrite_c) {
		rewrite_c[0] = 0xc0 | rewrite_offset >> 8;
		rewrite_c[1] = rewrite_offset & 0xff;
		lbllen = &rewrite_c[2] - lbldata;
	}

	return lbllen;
}

#define PUSH_RAW(s, len)                                        \
do {                                                            \
  buf_len -= len;                                               \
  if (buf_len < 0) {                                            \
    L_DEBUG("unable to push %d byte structure (missing %d)",    \
            (int)len, -buf_len);                                \
    goto oob;                                                   \
  }                                                             \
  s = (void *)buf;                                              \
  buf += len;                                                   \
 } while(0)

#define PUSH(s) PUSH_RAW(s, sizeof(*s))

#define TO_BE16(s)              \
do {                            \
  uint16_t *i = (void *)s;      \
  void *e = i;                  \
  e += sizeof(*s);              \
  while (i != e) {              \
      *i = cpu_to_be16(*i);     \
      i++;                      \
    }                           \
} while(0)

#define PUSH_EXPANDED(e, saved, saved_max)                      \
do {                                                            \
  uint8_t _buf[256];                                            \
  int _r = escaped2ll(e, _buf, sizeof(_buf));                   \
  _r = _push_deduplicate(_buf, _r, buf, saved, saved_max);      \
  uint8_t *dst;                                                 \
  if (_r <=0 ) {                                                \
    goto oob;                                                   \
  }                                                             \
  PUSH_RAW(dst, _r);                                            \
  memcpy(dst, _buf, _r);                                        \
 } while(0)

static int _produce_reply_push_rr(ohp_query q,
                                  ohp_rr rr,
                                  uint8_t *buf, int buf_len,
                                  uint8_t *saved[], size_t saved_max)
{
  uint8_t *obuf = buf;
  uint8_t *b;
  uint8_t *sbuf = rr->drr.rdata;
  int slen = rr->drr.rdlen;
  int r;

  switch (rr->drr.rrtype)
    {
    case kDNSServiceType_SRV:
      /* From our point of view, SRV is just PTR with funny 8 byte
       * header at start. */
      {
        dns_rdata_srv srv;
        PUSH(srv);
        memcpy(srv, sbuf, sizeof(*srv));
        sbuf += sizeof(*srv);
        slen -= sizeof(*srv);
      }
      /* Intentional fall-through to label handling in PTR. */
    case kDNSServiceType_PTR:
      {
        char dbuf[kDNSServiceMaxDomainName];

        /* The relevant name is the only content of ptr. */
        if ((r = ll2escaped(sbuf, slen, dbuf, sizeof(dbuf)))<0)
          {
            L_ERR("error decoding ptr(/srv) record");
            return r;
          }
        const char *qb = TO_DNS(q->request->interface, dbuf);
        PUSH_EXPANDED(qb, saved, saved_max);
      }
      break;
      /* By default: We just push the data as is. */
    default:
      PUSH_RAW(b, slen);
      memcpy(b, sbuf, slen);
      break;
    }
  /* XXX - rewrite PTR, SRV (and perhaps also TXT). */
  return buf - obuf;
 oob:
  return DNS_RESULT_OOB;
}

int d2m_produce_reply(ohp_request req,
                      uint8_t *buf, int buf_len)
{
  uint8_t *obuf = buf;
  ohp_query q;
  ohp_rr rr;
  bool first = true;
  dns_msg msg = NULL;
  dns_query dq;
  dns_rr dr;
  int r, fallback_result = DNS_RESULT_OOB;
  const size_t saved_max = 128;
  uint8_t *saved[saved_max];

  _init_deduplicate(saved, saved_max, buf);
  PUSH(msg);
  memset(msg, 0, sizeof(*msg));
  msg->h = DNS_H_QR | DNS_H_AA;
  msg->id = req->dnsid;
  /* XXX - should we copy RD from original message like Lua code does?
   * why does it do that? hmm. */
  list_for_each_entry(q, &req->queries, head)
    {
      L_DEBUG(" producing reply for %s/%d", q->query, q->dq.qtype);
      if (first)
        {
          /* Push the query first. */
          PUSH_EXPANDED(q->query, saved, saved_max);
          PUSH(dq);
          msg->qdcount = 1;
          *dq = q->dq;
          TO_BE16(dq);
          fallback_result = buf - obuf;
          L_DEBUG(" fallback 1:%d", fallback_result);
          /* This is the shortest valid reply; message header + query. */
        }
      list_for_each_entry(rr, &q->rrs, head)
        {
          PUSH_EXPANDED(rr->name, saved, saved_max);
          PUSH(dr);
          r = _produce_reply_push_rr(q, rr, buf, buf_len, saved, saved_max);
          if (r == DNS_RESULT_OOB)
            goto oob;
          if (r < 0)
            return r;
          buf += r;
          buf_len -= r;
          *dr = rr->drr;
          if (first)
            msg->ancount++;
          else
            msg->arcount++;
          dr->rdlen = r; /* rewrite may have changed length */
          TO_BE16(dr);
          /* TO_BE16 won't cover BE32 -> convert TTL separately here. */
          dr->ttl = cpu_to_be32(rr->drr.ttl);
        }
      if (first)
        {
          /* This is second shortish valid reply; answers, but no
           * additional records. */
          fallback_result = buf - obuf;
          L_DEBUG(" fallback 2:%d", fallback_result);
          first = false;
          if (!msg->ancount)
            {
              msg->h |= DNS_H_RCODE(DNS_RCODE_NXDOMAIN);
              break;
            }
        }
    }
  if (first)
    {
      L_ERR("no query in d2m_produce_reply");
      return DNS_RESULT_ERROR;
    }
  TO_BE16(msg);
  return buf - obuf;
 oob:
  L_DEBUG("oob handler with %d result", fallback_result);
  if (msg)
    {
      /* Clearly no additional records didn't fit in. */
      msg->arcount = 0;

      /* If all answers didn't fit in either, clear ancount + return TC. */
      if (first)
        {
          msg->ancount = 0;
          msg->h |= DNS_H_TC;
        }
      TO_BE16(msg);
    }
  return fallback_result;
}
