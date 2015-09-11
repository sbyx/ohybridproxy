/*
 * $Id: test_client.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Jan  9 11:13:07 2014 mstenber
 * Last modified: Fri Sep 11 11:37:37 2015 mstenber
 * Edit time:     22 min
 *
 */

#define L_LEVEL 7

#include "dns2mdns.h"
#include "dns2mdns.c"

#include <assert.h>
#include <string.h>

void io_send_reply(io_request req)
{
  /* Test reply production - with too small, and sufficient buffer. */
  unsigned char buf[65535];
  int r;

  /* Too small payload tests are now in test_dns2mdns. */
  memset(buf, 42, sizeof(buf));
  r = b_produce_reply(req, buf, sizeof(buf));
  assert(r > 0);
  assert(buf[r] == 42);
  L_DEBUG("d2m_produce_reply produced %d bytes of something", r);
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
  b_req_init(&r);
  if (d2m_add_interface(argv[1], "home") < 0)
    {
      exit(1);
    }
  b_req_add_query(&r, argv[2],
                  argc > 3 ? atoi(argv[3]) : kDNSServiceType_ANY);
  b_req_start(&r);
  L_INFO("Entering event loop");
  uloop_run();

  /* Clean up - hopefully we won't leak memory if we do it right. */
  b_req_free(&r);
  _state_reset();
  return 0;
}
