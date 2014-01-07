/*
 * $Id: ohybridproxy.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon Jan  6 12:55:33 2014 mstenber
 * Last modified: Tue Jan  7 16:57:28 2014 mstenber
 * Edit time:     18 min
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void show_help(const char *prog)
{
  printf("%s [-a <ip>] [-h] <ifname>=<domain> [<ifname>=<domain> ..]\n", prog);
  printf(" -a binds to specific IP address\n");
  printf(" -h shows this help\n");
  printf(" For the given <ifname>(s), <domain> requests are mapped to .local\n"
         " and handled on the interface. Reverse queries are handled based\n"
         " on closest interface with configured domain.\n");
}

int main(int argc, char **argv)
{
  int i, r;
  char *addr = NULL;
  const char *prog = argv[0];

  while ((r = getopt(argc, argv, "ha:"))>0)
    switch(r)
      {
      case 'a':
        addr = optarg;
        break;
      case 'h':
      default:
        goto help;
      }

  argc -= optind;
  argv += optind;

  if (argc == 0)
    {
    help:
      show_help(prog);
      exit(0);
    }
  for (i = 0 ; i < argc ; i++)
    {
      char *ifname = argv[i];
      char *domain = strchr(ifname, '=');
      if (!domain)
        {
          fprintf(stderr, "Invalid domain specification #%d (no =): %s",
                  i, ifname);
          exit(1);
        }
      *domain++ = 0;
      /* Now we can do stuff with ifname+domain. */
    }
  return 0;
}
