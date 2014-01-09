/*
 * $Id: test_client.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Jan  9 11:13:07 2014 mstenber
 * Last modified: Thu Jan  9 12:05:15 2014 mstenber
 * Edit time:     9 min
 *
 */

#define L_LEVEL 7

#include "dns2mdns.h"
#include "dns2mdns.c"

void d2m_req_send(struct ohp_request *req __unused)
{
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
  d2m_add_interface(argv[1], ".local.");
  d2m_req_add_query(&r, argv[2],
                    argc > 3 ? atoi(argv[3]) : kDNSServiceType_ANY);
  d2m_req_start(&r);
  L_INFO("Entering event loop");
  uloop_run();

  /* Clean up - hopefully we won't leak memory if we do it right. */
  _req_free(&r);
  DNSServiceRefDeallocate(conn);
  return 0;
}
