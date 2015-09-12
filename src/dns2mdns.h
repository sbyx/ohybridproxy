/*
 * $Id: dns2mdns.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:23:19 2014 mstenber
 * Last modified: Sat Sep 12 10:38:22 2015 mstenber
 * Edit time:     58 min
 *
 */

#pragma once

#include "dns_proto.h"

/* How many milliseconds can we wait for results until we're done?
 * MDNS operates on sub-second speed, and some DNS clients starts
 * resending at second. Sigh. */
#define MAXIMUM_REQUEST_DURATION_IN_MS 500

/*
 * This module handles actual interface with the lower level mdns, and
 * produces the dns response back.
 *
 * The rewriting is done based on configuration initialized by calling
 * d2m_add_interface call. The dns2mdns.c implements b_* interface
 * specified in io.h.
 */

/*
 * Add one real system interface, with specified domain (reverse
 * happens automatically) to the request processing logic.
 */
bool d2m_add_interface(const char *ifname, const char *domain);
