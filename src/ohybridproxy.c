#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/utils.h>
#include <libubox/ustream.h>

#include "ohybridproxy.h"

static struct list_head requests = LIST_HEAD_INIT(requests);
static void ohp_handle_udp(struct uloop_fd *fd, __unused unsigned int events);
static void ohp_handle_tcp_conn(struct uloop_fd *fd, __unused unsigned int events);

static struct uloop_fd udpsrv = { .cb = ohp_handle_udp };
static struct uloop_fd tcpsrv = { .cb = ohp_handle_tcp_conn };



struct ohp_request {
	struct list_head head;
	struct uloop_timeout timeout;
	char *query;
	uint16_t qtype;
	uint16_t dhcpid;
	size_t maxlen;
	bool udp;
};

struct ohp_request_tcp {
	struct ohp_request req;
	struct ustream_fd conn;
};

struct ohp_request_udp {
	struct ohp_request req;
	size_t addrlen;
	struct sockaddr addr[];
};


static bool ohp_parse_request(struct ohp_request *req, const uint8_t *buf, size_t len, bool udp)
{
	if (!req || len <= 12)
		return false;

	const uint8_t *question = &buf[12];
	const uint8_t *eom = &buf[len];
	const uint16_t *hdr = (uint16_t*)buf;

	if (ntohs(hdr[2]) != 1 || hdr[3] || hdr[4])
		return false;

	char domain[256];
	int complen = dn_expand(buf, eom, &buf[12], domain, sizeof(domain));
	const uint8_t *opt = &question[complen + 4]; // Point to next RR (should be OPT or EOM)
	if (complen <= 0 || opt > eom)
		return false;

	req->dhcpid = hdr[0];
	req->query = strdup(domain);
	req->qtype = question[complen] << 8 | question[complen + 1];
	req->udp = udp;
	req->maxlen = (udp) ? 512 : 65535;

	// Test for OPT-RR (EDNS)
	if (udp && &opt[10] <= eom && opt[0] == 0 && opt[1] == 0 && opt[2] == 41) {
		opt += 3; // Skip empty name and type field

		if ((req->maxlen = ((size_t)opt[0]) << 8 | ((size_t)opt[1])) < 512)
			req->maxlen = 512;

		opt += 6; // Skip class and TTL field

		// Read RDATA length
		uint16_t rdlen = ((uint16_t)opt[0]) << 8 | ((uint16_t)opt[1]);
		opt += 2;

		if (&opt[rdlen] > eom)
			return false;

		// TODO: Parse LLQ options?
	}

	L_DEBUG("Parsed a request %hx of type %u for %s with max response length %ldB",
			req->dhcpid, req->qtype, req->query, (long)req->maxlen);
	list_add(&req->head, &requests);
	return true;
}


static void ohp_free_request(struct ohp_request *req)
{
	if (req->head.next)
		list_del(&req->head);
	free(req->query);
	free(req); // TODO: should maybe use container_of before, but it's the first entry anyway
}


static void ohp_handle_udp(struct uloop_fd *fd, __unused unsigned int events)
{
	union {
		struct sockaddr_in6 sin6;
		struct sockaddr sa;
	} addr;
	socklen_t addrlen = sizeof(addr);

	uint8_t buf[512];
	ssize_t len;
	while ((len = recvfrom(fd->fd, buf, sizeof(buf), MSG_TRUNC, &addr.sa, &addrlen)) >= 0 ||
			errno != EWOULDBLOCK) {
		if (len < 0 || len > (ssize_t)sizeof(buf))
			continue;

		L_DEBUG("Received %ld bytes via UDP", (long)len);

		struct ohp_request_udp *req = calloc(1, sizeof(*req) + addrlen);
		req->addrlen = addrlen;
		memcpy(req->addr, &addr, addrlen);

		if (!ohp_parse_request(&req->req, buf, (size_t)len, true)) {
			L_DEBUG("UDP request was invalid");
			// TODO: reply with DNS FORMERR here?
			free(req);
		}
	}
}

// More data was received from TCP connection
static void ohp_handle_tcp_data(struct ustream *s, __unused int bytes_new)
{
	int pending;
	uint8_t *data = (uint8_t*)ustream_get_read_buf(s, &pending);
	struct ohp_request_tcp *tcp = container_of(s, struct ohp_request_tcp, conn);

	L_DEBUG("TCP connection %i has %i bytes pending", tcp->conn.fd.fd, pending);

	// Basic sanity check
	if (pending < 2 || tcp->req.query || tcp->req.head.next)
		return;

	size_t len = ((size_t)data[0]) << 8 | data[1];
	// Do we have the full message already
	if (pending < (int)len + 2)
		return;

	L_DEBUG("TCP connection %i has received the full request", tcp->conn.fd.fd);

	// Parse request
	if (!ohp_parse_request(&tcp->req, &data[2], len, false)) {
		L_DEBUG("TCP connection %i received invalid request", tcp->conn.fd.fd);
		ustream_state_change(s); // Trigger failure
		return;
	}

	// Cancel read timeout
	uloop_timeout_cancel(&tcp->conn.stream.state_change);
}


// TCP transmission has ended, either because of success or timeout or other error
static void ohp_handle_tcp_done(struct ustream *s)
{
	struct ohp_request_tcp *tcp = container_of(s, struct ohp_request_tcp, conn);
	ustream_free(s);
	close(tcp->conn.fd.fd);
	ohp_free_request(&tcp->req);
}


static void ohp_handle_tcp_conn(struct uloop_fd *fd, __unused unsigned int events)
{
	int clientfd;
	while ((clientfd = accept(fd->fd, NULL, NULL)) >= 0 || errno != EWOULDBLOCK) {
		if (clientfd < 0)
			continue;

		L_DEBUG("Incoming TCP connection %i", clientfd);

		struct ohp_request_tcp *tcp = calloc(1, sizeof(*tcp));
		tcp->conn.stream.r.max_buffers = 514;
		tcp->conn.stream.r.buffer_len = 256;
		tcp->conn.stream.notify_read = ohp_handle_tcp_data;
		tcp->conn.stream.notify_state = ohp_handle_tcp_done;
		ustream_fd_init(&tcp->conn, clientfd);

		// Timeout reading from TCP after 3s
		uloop_timeout_set(&tcp->conn.stream.state_change, 3000);
	}
}


void show_help(const char *prog)
{
	printf("%s [-a <ip>] [-p <port>] [-h] <ifname>=<domain> [<ifname>=<domain> ..]\n", prog);
	printf(" -a binds to specific IP address\n");
	printf(" -p binds to specific UDP port (default 53)\n");

	printf(" -h shows this help\n");
	printf(" For the given <ifname>(s), <domain> requests are mapped to .local\n"
		" and handled on the interface. Reverse queries are handled based\n"
		" on closest interface with configured domain.\n");
}


int main(int argc, char *const argv[])
{
	const char *prog = argv[0];
	int c, i;
	const char *bindaddr = NULL;
	const char *bindport = "53";

	openlog("ohybridproxy", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();
	while ((c = getopt(argc, argv, "a:p:h")) != -1) {
		switch (c) {
		case 'a':
			bindaddr = optarg;
			break;

		case 'p':
			bindport = optarg;
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
	udpsrv.fd = usock(USOCK_UDP | USOCK_SERVER | USOCK_NONBLOCK, bindaddr, bindport);
	tcpsrv.fd = usock(USOCK_TCP | USOCK_SERVER | USOCK_NONBLOCK, bindaddr, bindport);

	if (udpsrv.fd < 0 || tcpsrv.fd < 0) {
		L_ERR("Unable to bind DNS-socket: %s", strerror(errno));
		return 2;
	}

	uloop_fd_add(&udpsrv, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	uloop_fd_add(&tcpsrv, ULOOP_READ | ULOOP_EDGE_TRIGGER);


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
	}

	uloop_run();
	return 0;
}