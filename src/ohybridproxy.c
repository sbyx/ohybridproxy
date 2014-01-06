/*
 * $Id: ohybridproxy.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon Jan  6 12:55:33 2014 mstenber
 * Last modified: Mon Jan  6 13:11:59 2014 mstenber
 * Edit time:     1 min
 *
 */

#include <stdlib.h>
#include <unistd.h>

void show_help()
{
}

int main(int argc, char **argv)
{
  int r;
  while ((r = getopt(argc, argv, "h"))>0)
    switch(r)
      {
      case 'h':
        show_help();
        exit(0);
        break;
      default:
        show_help();
        exit(0);
      }
  /* TBD */
  return 0;
}
