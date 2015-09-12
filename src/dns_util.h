/*
 * $Id: dns_util.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 11:41:22 2014 mstenber
 * Last modified: Sat Sep 12 11:40:46 2015 mstenber
 * Edit time:     94 min
 *
 */

#ifndef DNS_UTIL_H
#define DNS_UTIL_H

#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* in6_addr */
#include <netinet/in.h>

/* Single (binary) label max length. */
#define DNS_MAX_L_LEN 64

/* Maximum result size of *2ll */
#define DNS_MAX_LL_LEN 256

/* Maximum result size of *2escaped */
#define DNS_MAX_ESCAPED_LEN 1009

/* Single (escaped) label max length (approximation) */
#define DNS_MAX_ESCAPED_L_LEN 256

/* This error indicates that outbut buffer was too small. */
#define DNS_RESULT_OOB -1

/* This error indicates that something else went awry; typically,
 * input is malformed in some way. */
#define DNS_RESULT_ERROR -2

/* Label compression encountered but not supported */
#define DNS_RESULT_LC_NOT_SUPPORTED -3

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
 *
 * There's few reasons why not to use dn_*: Extra library, and
 * encoding that is _NOT_ consistent what dns_sd.h claims to require
 * (and some suspicious habits w.r.t. trailing ., ordering of results,
 * etc, which seem to vary by implementation).
 */

#define PUSH_LABEL(ll, ll_left, l, l_len)               \
do {                                                    \
  ll_left -= l_len + 1;                                 \
  if (ll_left < 0)                                      \
    {                                                   \
      L_DEBUG("lacking %d/%d bytes (push label body)",  \
              -ll_left, l_len + 1);                     \
      return DNS_RESULT_OOB;                            \
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
 * empty label if it is not present within escaped.
 *
 * Return value is number of bytes written to ll or less than zero in
 * case of error.
 */
static inline
int escaped2ll(const char *escaped, uint8_t *ll, int ll_left)
{
  uint8_t *oll = ll;
  int last_size = -1;
  char c;
  uint8_t label[DNS_MAX_ESCAPED_LEN], *l = label, *le = label + sizeof(label);
  char buf[4];
  int i;

  if (ll_left <= 0)
    {
      L_DEBUG("no output string available");
      return DNS_RESULT_OOB;
    }
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
                      return DNS_RESULT_ERROR;
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
              return DNS_RESULT_ERROR;
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
      return DNS_RESULT_OOB;                            \
    }                                                   \
  *(escaped++) = c;                                     \
 } while(0)

/*
 * Convert single label to escaped string. Note that l contains
 * _body_, and l_left is assumed to have been picked from the label
 * already.
 */
static inline
int l2escaped(const uint8_t *l, int l_len, char *escaped, int escaped_left)
{
  char *oescaped = escaped;
  int i;

  for (i = 0 ; i < l_len ; i++)
    {
      uint8_t d = *(l++);
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
              return DNS_RESULT_OOB;
            }
          memcpy(escaped, buf, 4);
          escaped += 4;
        }
    }
  return escaped - oescaped;
}


/*
 * Convert label list to escaped string.
 *
 * Return the number of bytes consumed (escaped string will be null
 * terminated) or less than zero in case of error.
 */
static inline
int ll2escaped(const uint8_t *base, const uint8_t *ll, int ll_left, char *escaped, int escaped_left)
{
  const uint8_t *oll = ll;
  int r;

  if (escaped_left <= 0)
    {
      L_DEBUG("no output string available");
      return DNS_RESULT_OOB;
    }
  while (1)
    {
      if (!ll_left--)
        {
          L_DEBUG("out of input string (before last null label)");
          return DNS_RESULT_ERROR;
        }
      uint8_t c = *(ll++);

      /* Empty label terminates the label list. */
      if (c)
        {
          if ((c & (64|128)) == (64|128))
            {
              if (!base)
                return DNS_RESULT_LC_NOT_SUPPORTED;
              if (!ll_left--)
                {
                  L_DEBUG("out of input string (before last null label)");
                  return DNS_RESULT_ERROR;
                }
              uint8_t c2 = *(ll++);
              const uint8_t *nofs = base + ((c % 64) << 8) + c2;
              r = ll2escaped(base, nofs, ll + ll_left - nofs, escaped, escaped_left);
              if (r < 0)
                return r;
              return ll - oll;
            }
          if (c & (64|128))
            {
              return DNS_RESULT_ERROR;
            }
          ll_left -= c;
          if (ll_left < 0)
            {
              L_DEBUG("%d/%d bytes of label body missing", -ll_left, c);
              return DNS_RESULT_ERROR;
            }
          r = l2escaped(ll, c, escaped, escaped_left);
          if (r < 0)
            return r;
          ll += c;
          escaped += r;
          escaped_left -= r;
        }
      if (!c)
        break;
      PUSH_CHAR('.');
    }
  PUSH_CHAR(0);
  return ll - oll;
}

/*
 * Convert escaped string with IPv6 reverse address to real IPv6 address.
 *
 * Return true in case the operation succeeded, and FALSE otherwise.
 */
static inline
bool escaped2ipv6(const char *escaped, struct in6_addr *addr)
{
  char tbuf[DNS_MAX_ESCAPED_LEN], *c = tbuf, *d;
  int i;

  if (strlen(escaped) >= DNS_MAX_ESCAPED_LEN)
    {
      L_ERR("escaped2ipv6: too long input");
      return false;
    }
  strcpy(tbuf, escaped);
  for (i = 31 ; i >= 0 ; i--)
    {
      if (!(d = strchr(c, '.')))
        {
          L_ERR("escaped2ipv6: too short label");
          return false;
        }
      *d++ = 0;
      long l = strtol(c, NULL, 16);
      if (!(l >= 0 && l < 16))
        {
          L_ERR("escaped2ipv6: invalid single label %s", c);
          return false;
        }
      if (i % 2)
        addr->s6_addr[i/2] = l;
      else
        addr->s6_addr[i/2] |= l << 4;
      c = d;
    }
  /* The rest should be ip6.arpa. or we're in trouble */
  if (strcasecmp(c, "ip6.arpa."))
    {
      L_ERR("escaped2ipv6: invalid leftovers:%s", c);
      return false;
    }
  return true;
}

/*
 * Convert IPv6 address to escaped label list with IPv6 reverse address.
 *
 * NOTE: Bad things happen if the buffer is not of sufficient size.
 */
static inline
void ipv62escaped(const struct in6_addr *addr, char *escaped)
{
  int i;
  for (i = 15 ; i >= 0 ; i--)
    {
      sprintf(escaped, "%x.%x.",
              addr->s6_addr[i] % 0x10,
              addr->s6_addr[i] / 0x10);
      escaped += strlen(escaped);
    }
  strcpy(escaped, "ip6.arpa.");
}

#undef PUSH_CHAR

#endif /* DNS_UTIL_H */
