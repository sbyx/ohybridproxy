/*
 * $Id: cache.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Sat Sep 12 19:18:06 2015 mstenber
 * Last modified: Tue Sep 15 11:47:20 2015 mstenber
 * Edit time:     69 min
 *
 */

#include "cache.h"
#include "dns_util.h"

#include <string.h>

/* cache the negative entries this long. */
#define NEGATIVE_CACHE_TTL 5

/* maximum TTL we want to store */
#define MAXIMUM_TTL 120

/* This is super-inefficient; however, if it ever becomes really a
 * problem, this is being used at too large scale already. So hello,
 * linked list. */
static struct list_head entries = LIST_HEAD_INIT(entries);

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

static int _reply_push_rr(cache_rr rr, uint32_t ttl_ofs,
                          uint8_t *buf, int buf_len,
                          uint8_t *saved[], size_t saved_max)
{
  uint8_t *obuf = buf;
  uint8_t *b;
  uint8_t *sbuf = rr->drr.rdata;
  int slen = rr->drr.rdlen;
  int r;
  dns_rr dr;

  PUSH_EXPANDED(rr->name, saved, saved_max);
  PUSH(dr);
  *dr = rr->drr;
  uint8_t *orbuf = buf;
  switch (rr->drr.rrtype)
    {
    case DNS_SERVICE_SRV:
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
    case DNS_SERVICE_PTR:
      {
        char dbuf[DNS_MAX_ESCAPED_LEN];

        /* The relevant name is the only content of ptr. */
        if ((r = ll2escaped(NULL, sbuf, slen, dbuf, sizeof(dbuf)))<0)
          {
            L_ERR("error decoding ptr(/srv) record");
            return r;
          }
        /* TBD: This rewrite needs to happen in mdns side!
         * const char *qb = TO_DNS(req->interface, dbuf); */
        PUSH_EXPANDED(dbuf, saved, saved_max);
      }
      break;
      /* By default: We just push the data as is. */
    default:
      PUSH_RAW(b, slen);
      memcpy(b, sbuf, slen);
      break;
      /* XXX - rewrite PTR, SRV (and perhaps also TXT). */
    }
  dr->rdlen = buf - orbuf;
  TO_BE16(dr);
  /* TO_BE16 won't cover BE32 -> convert TTL separately here. */
  uint32_t ttl = rr->drr.ttl;
  if (ttl_ofs > ttl)
    ttl = 0;
  else
    ttl -= ttl_ofs;
  dr->ttl = cpu_to_be32(ttl);
  return buf - obuf;
 oob:
  return DNS_RESULT_OOB;
}

static int _reply_push_rr_list(struct list_head *h,
                               uint32_t ttl_ofs,
                               uint8_t *buf, int buf_len,
                               uint16_t *rr_count,
                               uint8_t *saved[], size_t saved_max)
{
  uint8_t *obuf = buf;
  cache_rr rr;
  int r;
  int count = 0;

  list_for_each_entry(rr, h, head)
    {
      r = _reply_push_rr(rr, ttl_ofs, buf, buf_len, saved, saved_max);
      if (r < 0)
        return r;
      if (r)
        {
          buf += r;
          buf_len -= r;
          count++;
        }
    }
  *rr_count = count;
  return buf - obuf;
}

static int _entry_to_reply(cache_entry e, io_request req,
                           uint8_t *buf, int buf_len)
{
  uint8_t *obuf = buf;
  dns_msg msg = NULL;
  dns_query dq;
  int r;
  const size_t saved_max = 128;
  uint8_t *saved[saved_max];
  int ttl_ofs = (io_time() - e->cached_at) / IO_TIME_PER_SECOND;
  bool fit_an = false;

  _init_deduplicate(saved, saved_max, buf);
  PUSH(msg);
  memset(msg, 0, sizeof(*msg));
  msg->h = DNS_H_QR | DNS_H_AA;
  msg->id = req->dnsid;

  /* Push the query first. */
  PUSH_EXPANDED(e->query, saved, saved_max);
  PUSH(dq);
  msg->qdcount = 1;
  *dq = e->dq;
  TO_BE16(dq);

  r = _reply_push_rr_list(&e->an, ttl_ofs, buf, buf_len, &msg->ancount, saved, saved_max);
  if (r == DNS_RESULT_OOB)
    goto oob;
  buf += r;
  buf_len -= r;
  fit_an = true;

  r = _reply_push_rr_list(&e->ar, ttl_ofs, buf, buf_len, &msg->arcount, saved, saved_max);
  if (r == DNS_RESULT_OOB)
    goto oob;

  buf += r;
  buf_len -= r;

 oob:
  if (msg)
    {
      /* If all answers didn't fit in either, clear ancount + return TC. */
      if (!fit_an && !msg->ancount)
        msg->h |= DNS_H_TC;
      TO_BE16(msg);
      if (msg->qdcount == 0)
        return DNS_RESULT_OOB;
    }
  else
    return DNS_RESULT_OOB;
  return buf - obuf;
}

static void _entry_complete(cache_entry e, io_request req)
{
  ssize_t buf_len = req->maxlen ? req->maxlen : 512;
  uint8_t *buf = alloca(buf_len);

  buf_len = _entry_to_reply(e, req, buf, buf_len);
  io_send_reply(req, buf, buf_len);
}

static void _rr_free(cache_rr rr)
{
  free(rr->name);
  list_del(&rr->head);
  free(rr);
}


static void _rr_list_free(struct list_head *h)
{
  while (!list_empty(h))
    _rr_free(list_first_entry(h, struct cache_rr, head));
}

static void _entry_free_rrs(cache_entry e)
{
  _rr_list_free(&e->an);
  _rr_list_free(&e->ar);
}

static void _entry_free(cache_entry e)
{
  _entry_free_rrs(e);
  list_del(&e->lh);
  free(e->query);
  free(e);
}

cache_entry cache_register_request(io_request req, char *query, dns_query dq)
{
  cache_entry e, e2;
  io_time_t now = io_time();
  bool found = false;

  list_for_each_entry_safe(e, e2, &entries, lh)
    {
      if (e->valid_until && e->valid_until < now)
        {
          L_DEBUG(" .. freeing %s/%d", e->query, e->dq.qtype);
          _entry_free(e);
          continue;
        }
      if (strcmp(e->query, query)== 0 && memcmp(dq, &e->dq, sizeof(*dq))==0)
        {
          if (e->valid_until >= now)
            {
              L_DEBUG(" .. found valid cache for %s/%d", query, dq->qtype);
              _entry_complete(e, req);
              return e;
            }
          /* It's not valid. Is it actually being refreshed? */
          if (list_empty(&e->requests))
            {
              found = true;
              L_DEBUG(" .. restarting %s/%d", query, dq->qtype);
              break;
            }
          /* Yes, it is. Let's add us to the interested party list. */
          list_add(&req->in_cache, &e->requests);
          L_DEBUG(" .. waiting for %s/%d", query, dq->qtype);
          return e;
        }
    }
  if (!found)
    {
      /* Couldn't find entry - create new one. */
      e = calloc(1, sizeof(*e));
      if (!e)
        return NULL;
      e->query = strdup(query);
      if (!e->query)
        {
          free(e);
          return NULL;
        }
      e->dq = *dq;
      list_add(&e->lh, &entries);
      L_DEBUG(" .. new query %s/%d", query, dq->qtype);
    }
  else
    _entry_free_rrs(e);
  INIT_LIST_HEAD(&e->requests);
  INIT_LIST_HEAD(&e->an);
  INIT_LIST_HEAD(&e->ar);
  e->valid_until = 0;
  list_add(&req->in_cache, &e->requests);
  b_req_set_query(req, query, dq);
  req->e = e;
  io_req_start(req);
  return e;
}

void cache_entry_completed(cache_entry e)
{
  io_request req, req2;
  uint32_t lowest_ttl;
  bool found = !list_empty(&e->an);

  e->cached_at = io_time();
  if (found)
    {
      cache_rr rr;

      lowest_ttl = MAXIMUM_TTL;
      list_for_each_entry(rr, &e->an, head)
        if (rr->drr.ttl < lowest_ttl)
          lowest_ttl = rr->drr.ttl;
      list_for_each_entry(rr, &e->ar, head)
        if (rr->drr.ttl < lowest_ttl)
          lowest_ttl = rr->drr.ttl;
    }
  else
    lowest_ttl = NEGATIVE_CACHE_TTL;
  L_DEBUG("cache_entry_completed %s/%d - ttl:%d seconds",
          e->query, e->dq.qtype, lowest_ttl);
  e->valid_until = e->cached_at + ((io_time_t)lowest_ttl-1) * IO_TIME_PER_SECOND;
  list_for_each_entry_safe(req, req2, &e->requests, in_cache)
    {
      _entry_complete(e, req);
    }
  INIT_LIST_HEAD(&e->requests);
}

cache_rr
rrlist_add_rr(struct list_head *h,
              const char *rrname, dns_rr drr, const void *rdata)
{
  cache_rr rr = calloc(1, sizeof(*rr) + drr->rdlen);
  if (!rr)
    return NULL;
  if (!(rr->name = strdup(rrname)))
    {
      free(rr);
      return NULL;
    }
  L_DEBUG("adding rr %s / %d.%d ttl %d (%d rrdata)", rrname,
          drr->rrtype, drr->rrclass, drr->ttl, drr->rdlen);
  rr->drr = *drr;
  memcpy(rr->drr.rdata, rdata, drr->rdlen);
  list_add(&rr->head, h);
  return rr;
}
