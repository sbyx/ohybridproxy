/*
 * $Id: dns_util.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 11:41:22 2014 mstenber
 * Last modified: Wed Jan  8 13:20:47 2014 mstenber
 * Edit time:     41 min
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

#define PUSH_LABEL(ll, ll_left, l, l_len)       \
do {                                            \
  if (ll_left < (l_len + 1))                    \
    return -2;                                  \
  *(ll++) = l_len;                              \
  memcpy(ll, l, l_len);                         \
  ll += l_len;                                  \
  c = 0;                                        \
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
  uint8_t label[kDNSServiceMaxServiceName], *l, *le = label + sizeof(label);
  char buf[4];
  int i;

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
                  if (!(buf[i] = *escaped))
                    return -3;
                  if (!isdigit(buf[i]))
                    return -4;
                }
              buf[3] = 0;
              c = atoi(buf);
              break;
            }
          break;
        }
      if (c)
        {
          if (l == le)
            return -1;
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
    PUSH_LABEL(ll, ll_left, NULL, 0);
  return oll - ll;
}

#undef PUSH_LABEL

#define PUSH_CHAR(c)    \
do {                    \
  if (!escaped_left--)  \
    return -1;          \
  *(escaped++) = c;     \
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
        return -1;
      uint8_t c = *(ll++);

      /* Empty label terminates the label list. */
      if (c)
        {
          if (ll_left < c)
            return -2;
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
                    return -2;
                  memcpy(escaped, buf, 4);
                  escaped += 4;
                }
            }
        }
      PUSH_CHAR('.');
      if (!c)
        break;
    }
  PUSH_CHAR(0);
  return oll - ll;
}

#undef PUSH_CHAR

#endif /* DNS_UTIL_H */