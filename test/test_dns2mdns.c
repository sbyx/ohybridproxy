/*
 * $Id: test_dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:30:07 2014 mstenber
 * Last modified: Wed Jan  8 17:32:27 2014 mstenber
 * Edit time:     1 min
 *
 */

#define L_LEVEL 7

#include "dns2mdns.h"
#include "sput.h"
#include "ohybridproxy.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

void check_dns2mdns(void)
{
}

int main(int argc, char **argv)
{
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite(argv[0]); /* optional */
  sput_run_test(check_dns2mdns);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
