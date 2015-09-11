/*
 * $Id: io.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 */

#pragma once

#include "util.h"
#include "dns_proto.h"

#include <libubox/list.h>
#include <libubox/uloop.h>

typedef struct io_rr {
  struct list_head head;

  char *name;
  struct dns_rr drr;
} *io_rr;

typedef struct io_query {
  struct list_head head;

  /* Query that we are performing */
  char *query;
  struct dns_query dq;

  /* Backpointer to the request we are in. */
  struct io_request *request;

  /* The results of the particular (sub-)query. */
  struct list_head rrs;

  /* Private data pointer for the backend */
  void *b_private;
} *io_query;


typedef struct io_request {
  /* A list of _active_ requests (start called, but not yet stop). */
  struct list_head lh;

  /* Information from the DNS request by client. */
  uint16_t dnsid;
  size_t maxlen;
  bool udp;
  bool active;

  /* List of sub-queries. The first query is the 'main' one, and the
   * rest 'additional records' ones. */
  struct list_head queries;

  /* Number of running queries. */
  int running;

  /* Is it started at all? */
  bool started;

  /* Have we sent a response already? (refactor this to be rr-specific
   * in LLQ case). */
  bool sent;

  /* Active timeout. */
  struct uloop_timeout timeout;

  /* Private data pointer for the backend */
  void *b_private;
} *io_request;

/********************************************************* IO API (socket.c) */

/* Run the I/O loop, with socket at the address given. */
int io_run(const char *bindaddr, int bindport, int default_timeout_ms);

/* Reset the IO state => kill all ongoing requests. */
void io_reset();

/* Called by the backend, when it thinks it's done */
void io_send_reply(io_request req);

/*************************************************** IO structure API (io.c) */

/* Add query (if it does not already exist); only new query is returned. */
io_query io_req_add_query(io_request req, const char *query, uint16_t qtype);

/* Start/Stop whole request */
void io_req_start(io_request req);
void io_req_stop(io_request req);

/* Start processing a query; if it returns false, it failed immediately. */
bool io_query_start(io_query q);

/* Stop processing; return true if some query is still alive */
bool io_query_stop(io_query q);

/* Add RR to the query results */
io_rr io_query_add_rr(io_query q, const char *rrname, dns_rr drr, const void *rdata);

/* Initialize/free io-side structures of a request */
void io_req_init(io_request req);
void io_req_free(io_request req);

/************************************************** IO -> Backend API (X.c)  */

/* Start/stop processing of a query. */
bool b_query_start(io_query q);
void b_query_stop(io_query q);

/* Free the b_private, if any */
void b_query_free(io_query q);

/* All queries are done */
void b_queries_done(io_request req);

/* Produce reply to the pre-allocated buffer. Return value is the
 * number of bytes used, or -1 if the reply buffer is too small. */
int b_produce_reply(io_request req, uint8_t *buf, int buf_len);

/* Initialize/free backend-side structures of a request */
void b_req_init(io_request req);
void b_req_free(io_request req);

typedef int64_t io_time_t;
#define IO_TIME_MAX INT64_MAX
#define IO_TIME_PER_SECOND 1000

// Get current monotonic clock with millisecond granularity
static inline io_time_t io_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((io_time_t)ts.tv_sec * IO_TIME_PER_SECOND) +
			((io_time_t)ts.tv_nsec / (1000000000 / IO_TIME_PER_SECOND));
}
