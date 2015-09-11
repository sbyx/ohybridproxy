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

#include <libubox/list.h>

typedef struct io_request {
  /* Information from the DNS request by client. */
  uint16_t dnsid;
  size_t maxlen;
  bool udp;
  bool active;

  /* Private data pointer for the backend */
  void *b_private;
} *io_request;

int io_run(const char *bindaddr, int bindport);
void io_send_reply(io_request req);


/*
 * These two calls are used to start/stop underlying processing of a
 * request.
 */
void b_req_start(io_request req);
void b_req_stop(io_request req);

/* Add query (if it does not already exist). */
struct ohp_query *b_req_add_query(io_request req, const char *query, uint16_t qtype);

/* Produce reply to the pre-allocated buffer. Return value is the
 * number of bytes used, or -1 if the reply buffer is too small. */
int b_produce_reply(io_request req, uint8_t *buf, int buf_len);

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
