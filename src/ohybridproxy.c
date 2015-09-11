/*
 * $Id: ohybridproxy.c $
 *
 * Author: Steven Barth <steven@midlink.org>
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 */

#include "io.h"
#include "dns2mdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <libubox/uloop.h>

void show_help(const char *prog)
{
	printf("%s [-a <ip>] [-p <port>] [-h] <ifname>=<domain> [<ifname>=<domain> ..]\n", prog);
	printf(" -a binds to specific IP address\n");
	printf(" -p binds to specific UDP port (default 53)\n");

	printf(" -h shows this help\n\n");
	printf(" For the given <ifname>(s), matching <domain> requests are mapped to .local\n"
		" and handled on the interface. Reverse queries are attempted on all interfaces.\n");
}

int main(int argc, char *const argv[])
{
	const char *prog = argv[0];
	int c, i;
	const char *bindaddr = "::";
	int bindport = 53;

	openlog("ohybridproxy", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();
	while ((c = getopt(argc, argv, "46a:p:h")) != -1) {
		switch (c) {
		case '4':
		case '6':
			/* Ignored for now */
			break;
		case 'a':
			bindaddr = optarg;
			break;

		case 'p':
			bindport = atoi(optarg);
			break;

		default:
                  goto help;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
help:
		show_help(prog);
		return 1;
	}
	for (i = 0 ; i < argc ; i++) {
		char *ifname = argv[i];
		char *domain = strchr(ifname, '=');
		if (!domain) {
			fprintf(stderr, "Invalid domain specification #%d (no =): %s",
				i, ifname);
			return 1;
		}
		*domain++ = 0;
		/* Now we can do stuff with ifname+domain. */
		if (d2m_add_interface(ifname, domain)) {
			L_ERR("Failed to add interface %s: %s", ifname, strerror(errno));
			return 2;
		}
	}

	return io_run(bindaddr, bindport);
}
