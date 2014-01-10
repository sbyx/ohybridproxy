/*
 * $Id: test_client.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Jan  9 11:13:07 2014 mstenber
 * Last modified: Thu Jan  9 22:29:37 2014 mstenber
 * Edit time:     19 min
 *
 */

#define L_LEVEL 7

#include "dns2mdns.h"
#include "dns2mdns.c"

#include <assert.h>
#include <string.h>

void ohp_send_reply(struct ohp_request *req __unused)
{
  /* Test reply production - with too small, and sufficient buffer. */
  unsigned char buf[65535];
  int r;

  memset(buf, 42, sizeof(buf));
  r = d2m_produce_reply(req, buf, 10);
  assert(r < 0);
  assert(buf[0] == 42);
  r = d2m_produce_reply(req, buf, 12);
  assert(r == 12);
  assert(buf[r] == 42);
  r = d2m_produce_reply(req, buf, sizeof(buf));
  assert(r > 0);
  assert(buf[r] == 42);
  L_DEBUG("d2m_produce_reply produced %d bytes of something", r);
  uloop_end();
}

int main(int argc, char **argv)
{
  struct ohp_request r;

  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  memset(&r, 0, sizeof(r));
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
  r.maxlen = 65535;
  L_DEBUG("Configuring d2m");
  if (d2m_add_interface(argv[1], "home") < 0)
    {
      exit(1);
    }
  d2m_req_add_query(&r, argv[2],
                    argc > 3 ? atoi(argv[3]) : kDNSServiceType_ANY);
  d2m_req_start(&r);
  L_INFO("Entering event loop");
  uloop_run();

  /* Clean up - hopefully we won't leak memory if we do it right. */
  d2m_req_free(&r);
  DNSServiceRefDeallocate(conn);
  return 0;
}
