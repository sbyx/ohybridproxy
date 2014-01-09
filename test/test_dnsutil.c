/*
 * $Id: test_dnsutil.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 13:01:23 2014 mstenber
 * Last modified: Thu Jan  9 10:33:43 2014 mstenber
 * Edit time:     32 min
 *
 */

#define L_LEVEL 7

#include "dns_util.h"
#include "sput.h"
#include "ohybridproxy.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

/*
 * Make sure the encoding works both ways as expected.
 *
 * Notably, make sure that the canary is not touched and correctly
 * sized output buffers result in correct results.
 */

const char *test_strings[] = {
  "foo",
  "f\\.o",
  "f\\130o",
  "foo.local",
  NULL
};

int expected_binary_size[] = {
  1+3+1,
  1+3+1,
  1+3+1,
  1+3+1+5+1,
  1+3+1+5+1
};

void check_test_string(const char *s, int es, int es2)
{
  int j, k, r;
  uint8_t buf[128];
  char buf2[128];

  L_DEBUG("check_test_string %s => %d => %d", s, es, es2);
  for (j = -1 ; j < es + 2 ; j++)
    {
      buf[j+1] = 42;
      r = escaped2ll(s, j ? buf : NULL, j);
      L_DEBUG("j:%d got %d", j, r);
      sput_fail_unless(buf[j+1] == 42, "canary died");
      if (j < es)
        {
          sput_fail_unless(r < 0, "not error with insufficient buffer");
        }
      else if (r != es)
        {
          sput_fail_unless(false, "wrong result value");
        }
      else
        {
          int or = r;
          for (k = -1 ; k < es2 + 2 ; k++)
            {
              /* Try to re-encode it to buf2. */
              buf2[k+1] = 42;
              r = ll2escaped(buf, or, k ? buf2 : NULL, k);
              L_DEBUG("k:%d got %d", k, r);
              sput_fail_unless(buf2[k+1] == 42, "canary died");
              if (k < es2)
                {
                  sput_fail_unless(r < 0,
                                   "not error with insufficient buffer");
                }
              else
                {
                  if (r > 0)
                    L_DEBUG("escaped->ll->escaped:'%s'<>'%s'", s, buf2);
                  sput_fail_unless(r == es,
                                   "wrong number of bytes consumed");
                  sput_fail_unless((int)strlen(buf2) == es2 - 1,
                                   "wrong strlen");
                  sput_fail_unless(strncmp(s, buf2, strlen(s)) == 0,
                                   "strncmp fail");

                }
            }
        }
    }
}

void check_test_strings(void)
{
  int i;
  char buf[128];
  const char *s;

  for (i = 0 ; (s=test_strings[i]) ; i++)
    {
      /* 'es' are expected total size; in case of es2, that includes
       * zero final byte. */
      int es = expected_binary_size[i];
      sprintf(buf, "%s.", s);
      int es2 = strlen(buf) + 1;
      check_test_string(s, es, es2);
      check_test_string(buf, es, es2);
    }
}

int main(int argc, char **argv)
{
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("dns_util"); /* optional */
  sput_run_test(check_test_strings);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
