/*
 * $Id: test_dnsutil.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 13:01:23 2014 mstenber
 * Last modified: Sat Sep 12 11:40:01 2015 mstenber
 * Edit time:     47 min
 *
 */

#define L_LEVEL 7

#include "util.h"
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

const char *test_ipv6_strings[] = {
  /* valid case */
  "7.9.a.8.6.1.e.f.f.f.f.b.6.f.a.b.0.0.0.0.e.e.d.d.0.7.4.0.1.0.0.2.ip6.arpa.",
  /* too long */
  "7.9.a.8.6.1.e.f.f.f.f.b.6.f.a.b.0.0.0.0.e.e.d.d.0.7.4.0.1.0.0.2.2.ip6.arpa.",
  /* too short */
  "7.9.a.8.6.1.e.f.f.f.f.b.6.f.a.b.0.0.0.0.e.e.d.d.0.7.4.0.1.0.2.ip6.arpa.",
  /* too weird */
  "17.9.a.8.6.1.e.f.f.f.f.b.6.f.a.b.0.0.0.0.e.e.d.d.0.7.4.0.1.0.0.2.ip6.arpa.",
  /* non-ip6-arpa */
  "7.9.a.8.6.1.e.f.f.f.f.b.6.f.a.b.0.0.0.0.e.e.d.d.0.7.4.0.1.0.0.2.ip6.arpx.",
  NULL
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
              r = ll2escaped(NULL, buf, or, k ? buf2 : NULL, k);
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




void check_test_ipv6(void)
{
  int i;
  struct in6_addr a;
  char tbuf[DNS_MAX_ESCAPED_LEN];
  const char *s;

  for (i = 0 ; (s=test_ipv6_strings[i]) ; i++)
    {
      L_DEBUG("iteration #%d: %s", i, s);
      if (escaped2ipv6(s, &a))
        {
          sput_fail_unless(i == 0, "_first_ succeeds");
          ipv62escaped(&a, tbuf);
          sput_fail_unless(strcmp(s, tbuf) == 0, "ipv62escaped failed");
        }
      else
        {
          sput_fail_unless(i != 0, "non-first fails");
        }
    }
}

int main(int argc, char **argv)
{
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("dns_util"); /* optional */
  sput_run_test(check_test_strings);
  sput_run_test(check_test_ipv6);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
