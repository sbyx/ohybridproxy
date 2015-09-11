/*
 * $Id: dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:38:37 2014 mstenber
 * Last modified: Fri Sep 11 13:26:28 2015 mstenber
 * Edit time:     61 min
 *
 */

#include <stdlib.h>
#include <net/if.h>

#include "dns2mdns.h"
#include "io.h"
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

typedef struct d2m_conn_struct {
  DNSServiceRef service;
  struct uloop_fd fd;
} *d2m_conn;

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

static io_rr
_query_add_rr(ohp_query q, const char *name, dns_rr drr, const void *rdata)
{
  const char *rrname;

  if (q->use_query_name_in_reply)
    rrname = q->io->query;
  else
    {
      ohp_request req = q->io->request->b_private;
      rrname = TO_DNS(req->interface, name);
    }

  if (!rrname)
    return NULL;
  return io_query_add_rr(q->io, rrname, drr, rdata);
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
          if (ll2escaped(rdata, rdlen, buf, sizeof(buf))<0)
            {
              L_ERR("error decoding ptr record");
              return;
            }
          const char *qb = TO_DNS(req->interface, buf);
          if (!qb)
            return;
          if ((nq = io_req_add_query(req->io, qb, kDNSServiceType_SRV)))
            io_query_start(nq);
          if ((nq = io_req_add_query(req->io, qb, kDNSServiceType_TXT)))
            io_query_start(nq);
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
        const char *qb = TO_DNS(req->interface, buf);
        if (!qb)
            return;
        if ((nq = io_req_add_query(req->io, qb, kDNSServiceType_AAAA)))
          io_query_start(nq);
        if ((nq = io_req_add_query(req->io, qb, kDNSServiceType_A)))
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

bool b_query_start(io_query ioq)
{
  int flags = kDNSServiceFlagsForceMulticast;
  int ifindex;
  int err;
  d2m_interface ifo = NULL, ip;
  const char *qb = ioq->query;
  ohp_request req = ioq->request->b_private;
  ohp_query q;

  ioq->b_private = calloc(1, sizeof(*q));
  q = ioq->b_private;
  q->io = ioq;

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

void b_queries_done(io_request req)
{
  io_send_reply(req);
}

void b_query_stop(io_query ioq)
{
  ohp_query q = ioq->b_private;

  if (!q->conn)
    return;
  _conn_free(q->conn);
  q->conn = NULL;
}

void b_req_start(io_request ioreq __unused)
{

}

void b_req_stop(io_request ioreq __unused)
{
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
                                  io_rr rr,
                                  uint8_t *buf, int buf_len,
                                  uint8_t *saved[], size_t saved_max)
{
  uint8_t *obuf = buf;
  uint8_t *b;
  uint8_t *sbuf = rr->drr.rdata;
  int slen = rr->drr.rdlen;
  int r;
  ohp_request req = q->io->request->b_private;

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
        const char *qb = TO_DNS(req->interface, dbuf);
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

int b_produce_reply(io_request ioreq,
                    uint8_t *buf, int buf_len)
{
  ohp_request req = ioreq->b_private;
  uint8_t *obuf = buf;
  io_query q;
  io_rr rr;
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
  msg->id = ioreq->dnsid;
  /* XXX - should we copy RD from original message like Lua code does?
   * why does it do that? hmm. */
  list_for_each_entry(q, &req->io->queries, head)
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
          r = _produce_reply_push_rr(q->b_private,
                                     rr, buf, buf_len, saved, saved_max);
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
