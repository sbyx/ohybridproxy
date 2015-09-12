/*
 * $Id: socket.c $
 *
 * Author: Steven Barth <steven@midlink.org>
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
 *
 */


#include "io.h"
#include "cache.h"
#include "dns_util.h"

#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include <libubox/utils.h>
#include <libubox/ustream.h>

#include "dns_util.h"

/*********************************************** Low-level glue starts here  */

static void io_handle_udp(struct uloop_fd *fd, __unused unsigned int events);
static void io_handle_tcp_conn(struct uloop_fd *fd, __unused unsigned int events);
static void io_handle_tcp_write(struct ustream *fd, __unused int bytes);
static void io_handle_tcp_done(struct ustream *s);

static struct uloop_fd udpsrv = { .cb = io_handle_udp };
static struct uloop_fd tcpsrv = { .cb = io_handle_tcp_conn };

struct io_request_tcp {
	struct io_request req;
	struct ustream_fd conn;
};

struct io_request_udp {
	struct io_request req;
	size_t addrlen;
	struct sockaddr addr[];
};

io_time_t maximum_duration;

void io_send_reply(io_request req, uint8_t *buf, ssize_t len)
{
  if (req->sent)
    return;
  req->sent = true;

  if (req->udp) {
    struct io_request_udp *udp = container_of(req, struct io_request_udp, req);
    if (len > 0)
      sendto(udpsrv.fd, buf, len, 0, udp->addr, udp->addrlen);
    io_req_free(req);
    free(udp);
    return;
  }

  struct io_request_tcp *tcp = container_of(req, struct io_request_tcp, req);
  if (len > 0) {
    char tbuf[2] = { (len >> 8) & 0xff, (len >> 0) & 0xff };
    ustream_write(&tcp->conn.stream, (char*)tbuf, 2, false);
    ustream_write(&tcp->conn.stream, (char*)buf, len, false);
    uloop_timeout_set(&tcp->conn.stream.state_change, 3000); // TODO: Define write timeout
    io_handle_tcp_write(&tcp->conn.stream, 0); // Check if writing was immediate
  } else {
    io_handle_tcp_done(&tcp->conn.stream);
  }
}


static bool io_parse_request(io_request req, const uint8_t *buf, size_t len, bool udp)
{
	if (!req || len <= 12)
		return false;

	const uint8_t *question = &buf[12];
	const uint8_t *eom = &buf[len];
	const uint16_t *hdr = (uint16_t*)buf;

	if (ntohs(hdr[2]) != 1 || hdr[3] || hdr[4])
		return false;

	char domain[DNS_MAX_ESCAPED_LEN];
	int complen = ll2escaped(buf, question, eom - question, domain, sizeof(domain));
	const uint8_t *opt = &question[complen + 4]; // Point to next RR (should be OPT or EOM)
	if (complen <= 0 || opt > eom)
		return false;

	req->dnsid = be16_to_cpu(hdr[0]);
	req->udp = udp;
	req->maxlen = (udp) ? 512 : 65535;
        dns_query dq = (dns_query) (question + complen);
        FROM_BE16(dq);

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
	req->active = true;
        cache_register_request(req, domain, dq);
	return true;
}


static void io_handle_udp(struct uloop_fd *fd, __unused unsigned int events)
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

		struct io_request_udp *req = calloc(1, sizeof(*req) + addrlen);
		req->addrlen = addrlen;
		memcpy(req->addr, &addr, addrlen);
		io_req_init(&req->req);
		if (!io_parse_request(&req->req, buf, (size_t)len, true)) {
			L_DEBUG("UDP request was invalid");
			// TODO: reply with DNS FORMERR here?
			free(req);
		}
	}
}

// More data was received from TCP connection
static void io_handle_tcp_data(struct ustream *s, __unused int bytes_new)
{
	int pending;
	uint8_t *data = (uint8_t*)ustream_get_read_buf(s, &pending);
	struct ustream_fd *ufd = container_of(s, struct ustream_fd, stream);
	struct io_request_tcp *tcp = container_of(ufd, struct io_request_tcp, conn);

	L_DEBUG("TCP connection %i has %i bytes pending", tcp->conn.fd.fd, pending);

	// Basic sanity check
	if (pending < 2 /*|| uloop_timeout_remaining(&tcp->req.timeout) >= 0*/)
		return;

	size_t len = ((size_t)data[0]) << 8 | data[1];
	// Do we have the full message already
	if (pending < (int)len + 2)
		return;

	L_DEBUG("TCP connection %i has received the full request", tcp->conn.fd.fd);

	// Parse request
	if (!io_parse_request(&tcp->req, &data[2], len, false)) {
		L_DEBUG("TCP connection %i received invalid request", tcp->conn.fd.fd);
		ustream_state_change(s); // Trigger failure
		return;
	}

	// Cancel read timeout
	uloop_timeout_cancel(&tcp->conn.stream.state_change);
}

// Write notification
static void io_handle_tcp_write(struct ustream *fd, __unused int bytes)
{
	if (ustream_write_pending(fd)) {
		// Wrote response, recycle session
		struct ustream_fd *ufd = container_of(fd, struct ustream_fd, stream);
		struct io_request_tcp *tcp = container_of(ufd, struct io_request_tcp, conn);
		io_req_free(&tcp->req);
		io_req_init(&tcp->req);
	}
}

// TCP transmission has ended, either because of success or timeout or other error
static void io_handle_tcp_done(struct ustream *s)
{
	struct ustream_fd *ufd = container_of(s, struct ustream_fd, stream);
	struct io_request_tcp *tcp = container_of(ufd, struct io_request_tcp, conn);
	ustream_free(s);
	close(tcp->conn.fd.fd);
	io_req_free(&tcp->req);
	free(tcp);
}


static void io_handle_tcp_conn(struct uloop_fd *fd, __unused unsigned int events)
{
	int clientfd;
	while ((clientfd = accept(fd->fd, NULL, NULL)) >= 0 || errno != EWOULDBLOCK) {
		if (clientfd < 0)
			continue;

		L_DEBUG("Incoming TCP connection %i", clientfd);

		struct io_request_tcp *tcp = calloc(1, sizeof(*tcp));
		tcp->conn.stream.r.max_buffers = 514;
		tcp->conn.stream.r.buffer_len = 256;
		tcp->conn.stream.notify_read = io_handle_tcp_data;
		tcp->conn.stream.notify_state = io_handle_tcp_done;
		tcp->conn.stream.notify_write = io_handle_tcp_write;
		ustream_fd_init(&tcp->conn, clientfd);
		io_req_init(&tcp->req);

		// Timeout reading from TCP after 3s
		uloop_timeout_set(&tcp->conn.stream.state_change, 3000);
	}
}


/* not-usock; glibc getaddrinfo is evil, or at least, potentially
 * broken every now and then (e.g. numeric IP + serv => still does
 * lookups all over the place. which can fail). */

int nusock(const char *host, int port, int t)
{
	int s;
	int on = 1;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
	int ss_len;
	int pf = -1;

	memset(&ss, 0, sizeof(ss));
	if (inet_pton(AF_INET, host, &sin->sin_addr)) {
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		ss_len = sizeof(*sin);
		pf = AF_INET;
	} else if (inet_pton(AF_INET6, host, &sin6->sin6_addr)) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		ss_len = sizeof(*sin6);
		pf = AF_INET6;
	} else {
		L_ERR("unable to parse:%s", host);
		return -1;
	}
	s = socket(pf, t, 0);
	if (s < 0)
		perror("socket");
	else if (fcntl(s, F_SETFL, O_NONBLOCK) < 0)
		perror("fnctl O_NONBLOCK");
	else if (port
		 && setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		perror("setsockopt SO_REUSEADDR");
	else if (bind(s, (struct sockaddr *)&ss, ss_len) < 0)
		perror("bind");
	else if (t == SOCK_STREAM && listen(s, 1) < 0)
		perror("listen");
	else
		return s;
	return -1;
}

int io_run(const char *bindaddr, int bindport, int default_timeout_ms)
{
	udpsrv.fd = nusock(bindaddr, bindport, SOCK_DGRAM);
	if (udpsrv.fd < 0) {
		L_ERR("Unable to bind UDP DNS-socket %s/%d: %s", bindaddr, bindport, strerror(errno));
		return 2;
	}

	tcpsrv.fd = nusock(bindaddr, bindport, SOCK_STREAM);
	if (tcpsrv.fd < 0) {
		L_ERR("Unable to bind TCP DNS-socket %s/%d: %s", bindaddr, bindport, strerror(errno));
		return 2;
	}

	uloop_fd_add(&udpsrv, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	uloop_fd_add(&tcpsrv, ULOOP_READ | ULOOP_EDGE_TRIGGER);

	maximum_duration = default_timeout_ms;

	uloop_run();
	return 0;
}
