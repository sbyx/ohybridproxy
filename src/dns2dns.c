/*
 * $Id: dns2dns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 */

/*
 * This module does dns -> dns request handling.
 *
 * First query is used just to store what we were asking for, and all
 * it does is start the extra sub-queries.
 *
 * The sub-queries are done per configured target domain. The remote
 * DNS server is hardcoded to be ::1/53 (TBD).
 */

/*
 * TBD: Perhaps do TCP based requests too?
 */

#include "dns2dns.h"
#include "io.h"
#include "dns_util.h"
#include "cache.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>

static const char *local_addr = "::1";
static const char *remote_addr = "::1";
static int remote_port = 53;

static const char **domains = NULL;
static int n_domains = 0;

typedef struct d2d_query {
  uint16_t id;
} *d2d_query;

typedef struct d2d_request {
  struct uloop_fd ufd;
  io_request io;
  char *query;
  struct dns_query dq;
} *d2d_request;

void b_req_set_query(io_request ioreq, const char *query, dns_query dq)
{
  d2d_request req = ioreq->b_private;
  int i;
  const char *firstdot = strchr(query, '.');
  int len = firstdot - query + 1; /* include dot */

  req->query = strdup(query);
  req->dq = *dq;
  for (i = 0 ; i < n_domains ; i++)
    {
      char subq[DNS_MAX_ESCAPED_LEN];
      strncpy(subq, query, len);
      strcpy(subq+len, domains[i]);
      io_req_add_query(ioreq, subq, dq);
    }
}

#define MAX_UDP_LENGTH 512

bool b_query_start(io_query ioq)
{
  d2d_query q = calloc(1, sizeof(*q));
  d2d_request req = ioq->request->b_private;
  uint8_t *buf = alloca(MAX_UDP_LENGTH);
  uint8_t *eom = buf + MAX_UDP_LENGTH;
  struct sockaddr_in6 sin6 = {
    .sin6_family = AF_INET6,
    .sin6_port = htons(remote_port)
  };

  if (!buf)
    return false;
  ioq->b_private = q;
  q->id = random();
  inet_pton(AF_INET6, remote_addr, &sin6.sin6_addr);

  dns_msg m = (dns_msg) buf;
  memset(m, 0, sizeof(*m));
  m->id = q->id;
  m->h = DNS_H_RD;
  m->qdcount = 1;
  TO_BE16(m);
  uint8_t *p = buf + sizeof(*m);
  int complen = escaped2ll(ioq->query, p, eom - p);
  if (complen < 0)
    return false;
  p += complen;
  dns_query dq = (dns_query) p;
  p += sizeof(*dq);
  if (p > eom)
    return false;
  *dq = ioq->dq;
  TO_BE16(dq);
  return (sendto(req->ufd.fd, buf, p-buf, 0,
                 (struct sockaddr *)&sin6, sizeof(sin6)) > 0);
}

void b_query_stop(io_query ioq __unused)
{
}

void b_query_free(io_query q)
{
  if (!q->b_private)
    return;
  free(q->b_private);
}

static void _handle_udp(struct uloop_fd *ufd, __unused unsigned int events)
{
  union {
    struct sockaddr_in6 sin6;
    struct sockaddr sa;
  } addr;
  socklen_t addrlen = sizeof(addr);
  uint8_t buf[512];
  dns_msg m = (dns_msg) buf;
  ssize_t len;
  d2d_request req = container_of(ufd, struct d2d_request, ufd);
  io_query ioq;
  d2d_query q = NULL;

  while ((len = recvfrom(ufd->fd, buf, sizeof(buf), MSG_TRUNC,
                         &addr.sa, &addrlen)) >= 0
         || errno != EWOULDBLOCK) {
    if (len < (int)sizeof(*m) || len > (ssize_t)sizeof(buf))
      continue;

    FROM_BE16(m);
    /* TBD: Do we want to actually verify the address? */
    if (!(m->h & DNS_H_QR))
      {
        L_DEBUG("response w/o QR set");
        continue;
      }
    if (DNS_H_OPCODE(0) != (DNS_H_OPCODE(0xF) & m->h))
      {
        L_DEBUG("response w/ wrong opcode");
        continue;
      }
    if (m->qdcount != 1)
      {
        L_DEBUG("response w/ wrong qdcount (%d != 1", m->qdcount);
        continue;
      }

    uint8_t *question = buf + sizeof(*m);
    uint8_t *eom = buf + len;
    char domain[DNS_MAX_ESCAPED_LEN];
    int complen = ll2escaped(buf, question, eom - question, domain, sizeof(domain));
    bool found = false;
    if (complen <= 0)
      {
        L_DEBUG("ll->escape of query failed: %d", complen);
        continue;
      }
    /* Find the query with matching id + content */
    list_for_each_entry(ioq, &req->io->queries, head)
      {
        q = ioq->b_private;
        if (!ioq->stopped && q->id == m->id && strcmp(domain, ioq->query)==0)
          {
            found = true;
            break;
          }
      }
    if (!found)
      {
        L_DEBUG("no query found matching id %d / %s", q->id, domain);
        continue;
      }
    uint8_t *name = question + complen + 4;
    bool valid = true;
    while (name < eom)
      {
        complen = ll2escaped(buf, name, eom - name, domain, sizeof(domain));
        if (complen <= 0)
          {
            valid = false;
            L_DEBUG("ll->escape of rr failed: %d", complen);
            break;
          }
        dns_rr rr = (dns_rr) (name + complen);
        name += complen + sizeof(*rr);
        if (name > eom)
          {
            valid = false;
            L_DEBUG("last record too big (name/rr-header)");
            break;
          }
        struct dns_rr local_rr = *rr;
        FROM_BE16(&local_rr);
        local_rr.ttl = be32_to_cpu(rr->ttl);
        name += local_rr.rdlen;
        if (name > eom)
          {
            valid = false;
            L_DEBUG("last record too big (rrdata)");
            break;
          }
        if (m->ancount)
          {
            m->ancount--;
            rrlist_add_rr(&ioq->request->e->an, domain, &local_rr, rr->rdata);
          }
        else if (m->nscount)
          {
            m->nscount--;
          }
        else if (m->arcount)
          {
            m->arcount--;
          }
        else
          {
            L_DEBUG("bonus RR?!?");
            valid = false;
            break;
          }
      }
    if (valid)
      {
        L_DEBUG("got valid reply, shocking");
        /* Two options here; either optimistically just stop this
         * query, or stop whole request. The later results in better
         * performance so opting for that for now. */
        /* io_query_stop(ioq); */
        io_req_stop(req->io);
        break;
      }
  }
}



void b_req_init(io_request ioreq)
{
  d2d_request req = calloc(1, sizeof(*req));

  if (!req)
    return;
  ioreq->b_private = req;
  req->io = ioreq;
  req->ufd.fd = nusock(local_addr, 0, SOCK_DGRAM);
  req->ufd.cb = _handle_udp;
  uloop_fd_add(&req->ufd, ULOOP_READ | ULOOP_EDGE_TRIGGER);
}

void b_req_free(io_request ioreq)
{
  d2d_request req = ioreq->b_private;

  free(req->query);
  uloop_fd_delete(&req->ufd);
  free(req);
}

bool d2d_add_domain(const char *domain)
{
  if (!domains)
    {
      domains = malloc(sizeof(void *));
    }
  else
    {
      void *new = realloc(domains, sizeof(void *) * (n_domains + 1));
      if (!new)
        return false;
      domains = new;
    }
  domains[n_domains++] = domain;
  return true;
}
