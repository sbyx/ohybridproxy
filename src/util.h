/*
 * $Id: util.h $
 *
 * Author: Steven Barth <steven@midlink.org>
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
 *
 */

#pragma once

/* Anything up to INFO is compiled in by default; syslog can be used
 * to filter them out. DEBUG can be quite spammy and isn't enabled by
 * default. */
#define DEFAULT_L_LEVEL 6

#ifndef L_LEVEL
#define L_LEVEL DEFAULT_L_LEVEL
#endif /* !L_LEVEL */

#ifndef L_PREFIX
#define L_PREFIX ""
#endif /* !L_PREFIX */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <libubox/utils.h>

// Logging macros
#if L_LEVEL >= 3
#define L_ERR(...)	syslog(LOG_ERR, L_PREFIX __VA_ARGS__)
#else
#define L_ERR(...)
#endif

#if L_LEVEL >= 4
#define L_WARN(...)	syslog(LOG_WARNING, L_PREFIX __VA_ARGS__)
#else
#define L_WARN(...)
#endif

#if L_LEVEL >= 5
#define L_NOTICE(...)	syslog(LOG_NOTICE, L_PREFIX __VA_ARGS__)
#else
#define L_NOTICE(...)
#endif

#if L_LEVEL >= 6
#define L_INFO(...)	syslog(LOG_INFO, L_PREFIX __VA_ARGS__)
#else
#define L_INFO(...)
#endif

#if L_LEVEL >= 7
#define L_DEBUG(...)	syslog(LOG_DEBUG, L_PREFIX __VA_ARGS__)
#else
#define L_DEBUG(...)
#endif



// Some C99 compatibility

#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

#define FROM_BE16(s)            \
do {                            \
  uint16_t *i = (void *)s;      \
  void *e = i;                  \
  e += sizeof(*s);              \
  while (i != e) {              \
      *i = be16_to_cpu(*i);     \
      i++;                      \
    }                           \
} while(0)

#define TO_BE16(s)              \
do {                            \
  uint16_t *i = (void *)s;      \
  void *e = i;                  \
  e += sizeof(*s);              \
  while (i != e) {              \
      *i = cpu_to_be16(*i);     \
      i++;                      \
    }                           \
} while(0)
