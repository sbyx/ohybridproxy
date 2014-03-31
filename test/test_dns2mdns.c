/*
 * $Id: test_dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:30:07 2014 mstenber
 * Last modified: Mon Mar 31 13:28:05 2014 mstenber
 * Edit time:     71 min
 *
 */

/*
 * This module unit tests d2m as a whole, stubbing out the real
 * mdnsresponder and replacing it with .. nothing, really.
 */

#pragma GCC diagnostic ignored "-Wunused-parameter"

#define L_LEVEL 7

#include "ohybridproxy.h"
#include "sput.h"
#include "smock.h"

#include <libubox/uloop.h>
#define uloop_fd_add(fd, flags) 0
#define uloop_timeout_cancel(timeout)
#define uloop_timeout_set(timeout,v)
#include <dns_sd.h>

#define DNSServiceQueryRecord dummy_DNSServiceQueryRecord
#define DNSServiceRefDeallocate(x)
#define DNSServiceRefSockFD(x) 0

DNSServiceErrorType dummy_DNSServiceQueryRecord(DNSServiceRef *service,
                                                DNSServiceFlags flags,
                                                uint32_t ifindex,
                                                const char *name,
                                                uint16_t rrtype,
                                                uint16_t rrclass,
                                                DNSServiceQueryRecordReply cb,
                                                void *context);

#include "dns2mdns.c"

static void *first_dnsqr_context = NULL;

DNSServiceErrorType dummy_DNSServiceQueryRecord(DNSServiceRef *service,
                                                DNSServiceFlags flags,
                                                uint32_t ifindex,
                                                const char *name,
                                                uint16_t rrtype,
                                                uint16_t rrclass,
                                                DNSServiceQueryRecordReply cb,
                                                void *context)
{
  L_DEBUG("dummy_DNSServiceQueryRecord %s/%d @%d", name, rrtype, ifindex);
  smock_pull_string_is("dnsqr_name", name);
  smock_pull_int_is("dnsqr_rrtype", rrtype);
  sput_fail_unless(rrclass == kDNSServiceClass_IN, "invalid class");
  sput_fail_unless(cb == _service_callback, "wrong cb");
  sput_fail_unless(context, "NULL context is invalid");
  if (!first_dnsqr_context)
    first_dnsqr_context = context;
  *service = (void *)1;
  return smock_pull_int("dnsqr_result");
}

void check_reply_range(struct ohp_request *req, int r1, int r2)
{
  /* Make sure the result for any number within ]r1, r2[ is r1 */
  int i;
  uint8_t buf[512];
  int r;

  for (i = r1 ; i < r2 ; i++)
    {
      buf[i+1] = 42;
      r = d2m_produce_reply(req, buf, i);
      sput_fail_unless(r == r1, "same result");
      sput_fail_unless(buf[i+1] == 42, "canary alive");
    }
}

void ohp_send_reply(struct ohp_request *req)
{
  smock_pull("ohpsr");
  uint8_t buf[512];
  int or, r = d2m_produce_reply(req, buf, sizeof(buf));
  dns_msg msg;

  L_DEBUG("sufficient buffer reply got %d", r);
  sput_fail_unless(r > (int)sizeof(*msg),
                   "enough bytes from d2m_produce_reply");
  msg = (void *)buf;
  TO_BE16(msg);
  sput_fail_unless(msg->qdcount == 1, "qdcount");
  sput_fail_unless(msg->ancount == 1, "ancount");
  sput_fail_unless(msg->arcount == 3, "arcount");

  /* Fallback - no additional records */
  or = r;
  r = d2m_produce_reply(req, buf, r - 1);
  L_DEBUG("short push 1 got %d", r);
  sput_fail_unless(r > (int)sizeof(*msg),
                   "enough bytes from d2m_produce_reply");
  msg = (void *)buf;
  TO_BE16(msg);
  sput_fail_unless(msg->qdcount == 1, "qdcount2");
  sput_fail_unless(msg->ancount == 1, "ancount2");
  sput_fail_unless(msg->arcount == 0, "arcount2");
  check_reply_range(req, r, or);

  /* Fallback 2 - no records (just TC bit) */
  or = r;
  r = d2m_produce_reply(req, buf, r-1);
  L_DEBUG("short push 2 got %d", r);
  sput_fail_unless(r > (int)sizeof(*msg),
                   "enough bytes from d2m_produce_reply");
  msg = (void *)buf;
  TO_BE16(msg);
  sput_fail_unless(msg->qdcount == 1, "qdcount3");
  sput_fail_unless(msg->ancount == 0, "ancount3");
  sput_fail_unless(msg->arcount == 0, "arcount3");
  check_reply_range(req, r, or);

  /* Shorter than that should result in error */
  r = d2m_produce_reply(req, buf, r-1);
  L_DEBUG("short push 3 got %d", r);
  sput_fail_unless(r < 0, "really short buffer should be error");
}

#define DIF 42

#define SERVICE_NAME "dummyservice.local."
#define HOST_NAME "dummyhost.local."

void check_dns2mdns(void)
{
  struct ohp_request req;
  ohp_query q, srv_q, aaaa_q;
  uint8_t buf[256];
  int r, hdr_len;

  sput_fail_unless(_add_interface("dummy", DIF, "home") >= 0, "_add_interface");

  /* Case: Realistic request. */
  memset(&req, 0, sizeof(req));
  q = d2m_req_add_query(&req, "test.home.", kDNSServiceType_ANY);
  sput_fail_unless(q, "d2m_req_add_query failed");

  smock_push("dnsqr_name", "test.local.");
  smock_push_int("dnsqr_rrtype", kDNSServiceType_ANY);
  smock_push_int("dnsqr_result", kDNSServiceErr_NoError);
  d2m_req_start(&req);
  smock_is_empty();

  sput_fail_unless(req.running == 1, "1 running");

  /* Provide PTR response. Make sure it gets resolved. */
  r = escaped2ll(SERVICE_NAME, buf, sizeof(buf));
  sput_fail_unless(r > 0, "escaped2ll failed");

  /* Should result in SRV + TXT record sub-queries. */
  first_dnsqr_context = NULL;
  smock_push("dnsqr_name", SERVICE_NAME);
  smock_push_int("dnsqr_rrtype", kDNSServiceType_SRV);
  smock_push_int("dnsqr_result", kDNSServiceErr_NoError);

  smock_push("dnsqr_name", SERVICE_NAME);
  smock_push_int("dnsqr_rrtype", kDNSServiceType_TXT);
  smock_push_int("dnsqr_result", kDNSServiceErr_NoError);

  _service_callback(NULL,
                    kDNSServiceFlagsAdd,
                    DIF,
                    kDNSServiceErr_NoError,
                    "test.local.",
                    kDNSServiceType_PTR,
                    kDNSServiceClass_IN,
                    r,
                    buf,
                    120,
                    q);
  smock_is_empty();
  sput_fail_unless(req.running == 3, "3 running");


  /* Now, our fictional SRV query returns something.. */
  srv_q = first_dnsqr_context;
  hdr_len = sizeof(struct dns_rdata_srv);
  memset(buf, 0, hdr_len);
  r = escaped2ll(HOST_NAME, buf + hdr_len, sizeof(buf) - hdr_len);
  sput_fail_unless(r > 0, "escaped2ll failed");
  r += hdr_len;

  first_dnsqr_context = NULL;
  smock_push("dnsqr_name", HOST_NAME);
  smock_push_int("dnsqr_rrtype", kDNSServiceType_AAAA);
  smock_push_int("dnsqr_result", kDNSServiceErr_NoError);

  smock_push("dnsqr_name", HOST_NAME);
  smock_push_int("dnsqr_rrtype", kDNSServiceType_A);
  smock_push_int("dnsqr_result", kDNSServiceErr_NoError);

  _service_callback(NULL,
                    kDNSServiceFlagsAdd,
                    DIF,
                    kDNSServiceErr_NoError,
                    SERVICE_NAME,
                    kDNSServiceType_SRV,
                    kDNSServiceClass_IN,
                    r,
                    buf,
                    120,
                    srv_q);
  smock_is_empty();
  sput_fail_unless(req.running == 4, "4 running");

  /* And then return _two_ IPv6 addresses for the host. */
  aaaa_q = first_dnsqr_context;
  sput_fail_unless(aaaa_q, "no q");

  r = 16;
  memset(buf, 42, r);
  _service_callback(NULL,
                    kDNSServiceFlagsAdd | kDNSServiceFlagsMoreComing,
                    DIF,
                    kDNSServiceErr_NoError,
                    HOST_NAME,
                    kDNSServiceType_AAAA,
                    kDNSServiceClass_IN,
                    r,
                    buf,
                    120,
                    aaaa_q);
  smock_is_empty();

  aaaa_q = first_dnsqr_context;
  sput_fail_unless(aaaa_q, "no q");
  /* receiving one record should not terminate the AAAA query. */
  sput_fail_unless(req.running == 4, "4 running");

  r = 16;
  memset(buf, 43, r);
  _service_callback(NULL,
                    kDNSServiceFlagsAdd,
                    DIF,
                    kDNSServiceErr_NoError,
                    HOST_NAME,
                    kDNSServiceType_AAAA,
                    kDNSServiceClass_IN,
                    r,
                    buf,
                    120,
                    aaaa_q);
  smock_is_empty();
  sput_fail_unless(req.running == 3, "3 running");

  /* Ok. Let's pretend we get a timeout. */
  smock_push_bool("ohpsr", true);
  d2m_req_stop(&req);
  smock_is_empty();

  /* Free the structure. */
  d2m_req_free(&req);

  /* Clear the slate */
  _state_reset();
}

int main(int argc, char **argv)
{
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite(argv[0]); /* optional */
  sput_run_test(check_dns2mdns);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
