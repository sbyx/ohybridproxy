/*
 * $Id: test_client.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Jan  9 11:13:07 2014 mstenber
 * Last modified: Sat Sep 12 21:15:15 2015 mstenber
 * Edit time:     29 min
 *
 */

#define L_LEVEL 7

#include "dns2mdns.h"
#include "dns2mdns.c"
#include "io.c"
#include "cache.c"

#include <assert.h>
#include <string.h>

io_time_t maximum_duration = MAXIMUM_REQUEST_DURATION_IN_MS;
bool done = false;

void io_send_reply(io_request req __unused, uint8_t *buf __unused, ssize_t len)
{
  L_DEBUG("io_send_reply - produced %d bytes of something", (int)len);
  done = true;
  uloop_end();
}

int main(int argc, char **argv)
{
  struct io_request r = { .maxlen = 65535 };

  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  if (argc <= 2)
    {
      fprintf(stderr, "Usage: %s <ifname> <name> [type]\n", argv[0]);
      exit(1);
    }
  L_INFO("Initializing uloop");
  if (uloop_init() < 0)
    {
      fprintf(stderr, "Error in uloop_init\n");
      exit(1);
    }
  L_DEBUG("Configuring d2m");
  io_req_init(&r);
  if (!d2m_add_interface(argv[1], "home"))
    exit(1);
  struct dns_query dq = { .qtype =
                          argc > 3 ? atoi(argv[3]) : kDNSServiceType_ANY,
                          .qclass = DNS_CLASS_IN };
  cache_register_request(&r, argv[2], &dq);
  if (!done)
    {
      L_INFO("Entering event loop");
      uloop_run();
    }

  /* Clean up - hopefully we won't leak memory if we do it right. */
  io_req_free(&r);
  io_reset();
  return 0;
}
