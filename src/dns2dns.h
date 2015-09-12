/*
 * $Id: dns2dns.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 */

#pragma once

#include "util.h"

/* Add new domain for rewrites */
bool d2d_add_domain(const char *domain);
