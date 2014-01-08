/*
 * $Id: test_dnsutil.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 13:01:23 2014 mstenber
 * Last modified: Wed Jan  8 13:21:51 2014 mstenber
 * Edit time:     13 min
 *
 */

#include "dns_util.h"
#include "sput.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

/*
 * Make sure the encoding works both ways as expected.
 *
 * Notably, make sure that the canary is not touched and correctly
 * sized output buffers result in correct results.
 */

const char *test_strings[] = {
  "foo",
  "foo.local",
  "foo.local.",
  NULL
};

int expected_binary_size[] = {
  1+3+1,
  1+3+5+1,
  1+3+5+1
};

void check_test_strings(void)
{
  int i, j, k, r;
  const char *s;
  uint8_t buf[128];
  char buf2[128];

  for (i = 0 ; (s=test_strings[i]) ; i++)
    {
      int es = expected_binary_size[i];
      for (j = 0 ; j < es + 2 ; j++)
        {
          buf[j+1] = 42;
          r = escaped2ll(s, j ? buf : NULL, j);
          sput_fail_unless(buf[j+1] == 42, "canary died");
          if (j < es)
            {
              sput_fail_unless(r < 0, "not error with insufficient buffer");
            }
          else
            {
              sput_fail_unless(r == es, "wrong result value");
              int es2 = strlen(s) + s[strlen(s)-1] == '.' ? 0 : 1;
              for (k = 0 ; k < es2 + 2 ; k++)
                {
                  /* Try to re-encode it to buf2. */
                  buf2[k+1] = 42;
                  r = ll2escaped(buf, r, k ? buf2 : NULL, k);
                  sput_fail_unless(buf2[k+1] == 42, "canary died");
                  if (k < es2)
                    {
                      sput_fail_unless(r < 0,
                                       "not error with insufficient buffer");
                    }
                  else
                    {
                      sput_fail_unless(r == es,
                                       "wrong number of bytes consumed");
                      sput_fail_unless((int)strlen(buf2) == es2,
                                       "wrong strlen");
                      sput_fail_unless(strncmp(s, buf2, strlen(s)) == 0,
                                       "strncmp fail");

                    }
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
  /* openlog("test_dummy", LOG_CONS | LOG_PERROR, LOG_DAEMON); */
  sput_start_testing();
  sput_enter_suite("dns_util"); /* optional */
  sput_run_test(check_test_strings);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
