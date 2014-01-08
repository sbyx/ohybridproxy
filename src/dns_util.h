/*
 * $Id: dns_util.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 11:41:22 2014 mstenber
 * Last modified: Wed Jan  8 14:33:45 2014 mstenber
 * Edit time:     68 min
 *
 */

#ifndef DNS_UTIL_H
#define DNS_UTIL_H

#include <stdint.h>
#include <ctype.h>
#include <dns_sd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "ohybridproxy.h"

/*
 * This header file defines functions for transforming label list to
 * human readable dns_sd.h specified encoding and back again.
 *
 * As the hybrid proxy code needs to mostly deal with changing (human
 * readable) .local. trailer to something else, doing it in textual
 * form is probably more convenient. The dns_sd.h header doesn't
 * provide convenience API for this, unfortunately, and mDNSResponder
 * itself has wrong license, so reimplementing functionality here. Oh
 * well.
 */

#define PUSH_LABEL(ll, ll_left, l, l_len)               \
do {                                                    \
  ll_left -= l_len + 1;                                 \
  if (ll_left < 0)                                      \
    {                                                   \
      L_DEBUG("lacking %d/%d bytes (push label body)",  \
              -ll_left, l_len + 1);                     \
      return -2;                                        \
    }                                                   \
  *(ll++) = l_len;                                      \
  if (l_len) {                                          \
    memcpy(ll, l, l_len);                               \
    ll += l_len;                                        \
  }                                                     \
  c = 0;                                                \
 } while(0)

/*
 * Convert escaped string to a label list, potentially appending final
 * empty list if it is not present within escaped.
 *
 * Return value is number of bytes written to ll.
 */
int escaped2ll(const char *escaped, uint8_t *ll, int ll_left)
{
  uint8_t *oll = ll;
  int last_size = -1;
  char c;
  uint8_t label[kDNSServiceMaxServiceName], *l = label, *le = label + sizeof(label);
  char buf[4];
  int i;

  buf[3] = 0;
  while ((c = *(escaped++)))
    {
      switch (c)
        {
        case '.':
          last_size = l - label;
          PUSH_LABEL(ll, ll_left, label, last_size);
          l = label;
          break;
        case '\\':
          switch ((c = *(escaped++)))
            {
              /* Raw 'just this' case */
            case '.':
            case '\\':
              break;
            default:
              /* Better be _exactly_ 3 digits or we're in trouble ;) */
              for (i = 0 ; i < 3 ; i++)
                {
                  if (i)
                    c = *(escaped++);
                  if (!isdigit(c))
                    {
                      L_DEBUG("non-digit in location %d: %c", i, c);
                      return -3;
                    }
                  buf[i] = c;
                }
              c = atoi(buf);
              break;
            }
          break;
        }
      if (c)
        {
          if (l == le)
            {
              L_DEBUG("too long single label");
              return -1;
            }
          *(l++) = c;
        }
    }
  if (l != label)
    {
      /* There's pending stuff there. */
      last_size = l - label;
      PUSH_LABEL(ll, ll_left, label, last_size);
    }
  /* Terminate always with null label (if it didn't _just_ happen). */
  if (last_size != 0)
    PUSH_LABEL(ll, ll_left, label, 0);
  return ll - oll;
}

#undef PUSH_LABEL

#define PUSH_CHAR(c)                                    \
do {                                                    \
  if (!escaped_left--)                                  \
    {                                                   \
      L_DEBUG("out of space in escaped pushing %d", c); \
      return -1;                                        \
    }                                                   \
  *(escaped++) = c;                                     \
 } while(0)

/*
 * Convert label list to escaped string. Return the number of bytes
 * consumed (escaped string will be null terminated).
 */
int ll2escaped(uint8_t *ll, int ll_left, char *escaped, int escaped_left)
{
  uint8_t *oll = ll;
  int i;

  while (1)
    {
      if (!ll_left--)
        {
          L_DEBUG("out of input string (before last null label)");
          return -1;
        }
      uint8_t c = *(ll++);

      /* Empty label terminates the label list. */
      if (c)
        {
          ll_left -= c;
          if (ll_left < 0)
            {
              L_DEBUG("%d/%d bytes of label body missing", -ll_left, c);
              return -2;
            }
          for (i = 0 ; i < c ; i++)
            {
              uint8_t d = *(ll++);
              if (d == '\\' || d == '.')
                {
                  PUSH_CHAR('\\');
                  PUSH_CHAR(d);
                }
              else if (isprint(d))
                {
                  PUSH_CHAR(d);
                }
              else
                {
                  char buf[5];
                  sprintf(buf, "\\%03d", d);
                  escaped_left -= 4;
                  if (escaped_left < 0)
                    {
                      L_DEBUG("out of space in escaped: %d bytes",
                              -escaped_left);
                      return -2;
                    }
                  memcpy(escaped, buf, 4);
                  escaped += 4;
                }
            }
        }
      if (!c)
        break;
      PUSH_CHAR('.');
    }
  PUSH_CHAR(0);
  return ll - oll;
}

#undef PUSH_CHAR

#endif /* DNS_UTIL_H */
