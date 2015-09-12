/*
 * $Id: zonestitcher.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 */

#include "io.h"
#include "dns2dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <libubox/uloop.h>

static const char *bindaddr = "::";
static int bindport = 53;
static int timeout = 500;

void show_help(const char *prog)
{
  printf("%s [-a <ip>] [-p <port>] [-h] <domain> [<domain> ...]\n", prog);
  printf(" -a binds to specific IP address (default %s)\n", bindaddr);
  printf(" -p binds to specific UDP port (default %d)\n", bindport);
  printf(" -t per-request timeout (default %d)\n", timeout);

  printf(" -h shows this help\n\n");
  printf(" Any request sent to the local server for X.Y will be forwarded to \n"
         " the <domain>s as X.<domain>. Replies are rewritten back as X.Y\n"
         " records, if any.\n");
}

int main(int argc, char *const argv[])
{
  const char *prog = argv[0];
  int c, i;

  openlog("zonestitcher", LOG_PERROR | LOG_PID, LOG_DAEMON);
  uloop_init();
  while ((c = getopt(argc, argv, "46a:p:h")) != -1) {
    switch (c) {
    case 'a':
      bindaddr = optarg;
      break;

    case 'p':
      bindport = atoi(optarg);
      break;

    default:
      goto help;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc == 0) {
  help:
    show_help(prog);
    return 1;
  }
  for (i = 0 ; i < argc ; i++) {
    /* Now we can do stuff with ifname+domain. */
    if (!d2d_add_domain(argv[i])) {
      L_ERR("Failed to add domain %s: %s", argv[i], strerror(errno));
      return 2;
    }
  }

  return io_run(bindaddr, bindport, timeout);
}
