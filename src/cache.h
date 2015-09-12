/*
 * $Id: cache.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Sat Sep 12 19:18:06 2015 mstenber
 * Last modified: Sat Sep 12 20:32:13 2015 mstenber
 * Edit time:     17 min
 *
 */

/* Cache represents our current knowledge of what is out there.
 *
 * Notably, it has three features:
 * - requests can register to wait for it's population
 * - population can happen piecemeal (but with final 'this is ready' call)
 * - populated cache entry can be dumped as response to request
 *
 * As a result of this, we require only one place to handle all DNS
 * message _writing_ (=here). Where the data sourced from varies,
 * e.g. mdns, dns, or something else.
 */

/* Register to wait for population; once cache_entry_completed is
 * called for the entry, or the entry is already up to date,
 * io_send_reply(req, e) is called.
 */

#pragma once

#include "util.h"
#include "dns_proto.h"
#include "io.h"

#include <libubox/list.h>

typedef struct cache_rr {
  struct list_head head;

  char *name;
  struct dns_rr drr;
} *cache_rr;

typedef struct cache_entry {
  struct list_head lh;
  char *query;
  struct dns_query dq;
  struct list_head requests;
  struct list_head an;
  struct list_head ar;
  io_time_t cached_at;
  io_time_t valid_until;
} *cache_entry;

cache_entry cache_register_request(struct io_request *req,
                                   char *query, dns_query dq);
cache_rr rrlist_add_rr(struct list_head *h,
                    const char *rrname, dns_rr drr, const void *rdata);
void cache_entry_completed(cache_entry e);
