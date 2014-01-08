/*
 * $Id: dns2mdns.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan  8 17:38:37 2014 mstenber
 * Last modified: Wed Jan  8 19:19:28 2014 mstenber
 * Edit time:     30 min
 *
 */

/*
 * XXX - consider if we want to use the
 * kDNSServiceFlagsShareConnection or not. For the time being, writing
 * without, but it _would_ be somewhat more efficient..
 */

#include <stdlib.h>
#include <net/if.h>

#include "dns2mdns.h"
#include "ohybridproxy.h"
#include "dns_util.h"

typedef struct d2m_interface_struct {
  struct list_head lh;

  /* Domain assigned to the interface. */
  char domain[kDNSServiceMaxDomainName];

  /* Actual interface - name + index. */
  char ifname[IFNAMSIZ];
  uint32_t ifindex;
} *d2m_interface;

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);

static void
d2m_callback(DNSServiceRef service __unused,
             DNSServiceFlags flags,
             uint32_t ifindex,
             DNSServiceErrorType error,
             const char *name __unused,
             uint16_t rrtype,
             uint16_t rrclass __unused,
             uint16_t rdlen,
             const void *rdata,
             uint32_t ttl,
             void *context)
{
  struct ohp_request *req = context;

  if (error != kDNSServiceErr_NoError)
    {
      L_ERR("error %d from DNSServiceQueryRecord", error);
      return;
    }
  if (!(flags & kDNSServiceFlagsAdd))
    {
      L_INFO("non-add d2m_callback ignored for now (no LLQ)");
      return;
    }
}

static void
d2m_fd_callback(struct uloop_fd *u, unsigned int events)
{
  struct ohp_request *req = container_of(u, struct ohp_request, service_fd);
  int r;

  if ((r = DNSServiceProcessResult(req->service)) != kDNSServiceErr_NoError)
    {
      L_ERR("error %d in d2m_fd_callback", r);
    }
}

static bool
string_endswith(const char *s, const char *end)
{
  int l1 = strlen(s);
  int l2 = strlen(end);

  if (l1 < l2)
    return false;
  return strcmp(s + (l1 - l2), end) == 0;
}

void d2m_request_start(struct ohp_request *req)
{
  int flags = 0;
  int ifindex;
  int err;
  d2m_interface ifo = NULL, ip;

  /*
   * Look at the request. Either it ends with one of the domain's we
   * already have, or it ends with arpa, or we ignore it.
   */
  if (string_endswith(req->query, ".arpa."))
    {
      ifindex = 0;
      ifo = NULL;
    }
  else
    {
      list_for_each_entry(ip, &interfaces, lh)
        {
          if (string_endswith(req->query, ip->domain))
            {
              ifo = ip;
              break;
            }
        }

      if (!ifo)
        {
          L_INFO("impossible to serve query:%s", req->query);
          return;
        }
    }
  ifindex = ifo ? ifo->ifindex : 0;
  if ((err = DNSServiceQueryRecord(&req->service, flags, ifindex,
                                   req->query,
                                   req->qtype,
                                   kDNSServiceClass_IN,
                                   d2m_callback,
                                   req) != kDNSServiceErr_NoError))
    {
      L_ERR("Error %d initializing DNSServiceQueryRecord", err);
      abort();
    }
  req->service_fd.fd = DNSServiceRefSockFD(req->service);
  req->service_fd.cb = d2m_fd_callback;
  if (uloop_fd_add(&req->service_fd, ULOOP_READ) < 0)
    {
      L_ERR("Error in uloop_fd_add");
      abort();
    }
}

void d2m_request_stop(struct ohp_request *req)
{
  if (req->service)
    {
      (void)uloop_fd_delete(&req->service_fd);
      DNSServiceRefDeallocate(req->service);
    }
}

void d2m_add_interface(const char *ifname, const char *domain)
{
  d2m_interface ifo = calloc(1, sizeof(*ifo));
  /* Normalize the domain by encoding it to ll and back. */
  uint8_t buf[kDNSServiceMaxDomainName];
  int r;

  if (!ifo)
    {
      L_ERR("calloc failure");
      abort();
    }
  if ((r = escaped2ll(domain, buf, sizeof(buf))) < 0)
    {
      L_ERR("escaped2ll failed for %s", domain);
      return;
    }
  if ((r = ll2escaped(buf, r, ifo->domain, kDNSServiceMaxDomainName)) < 0)
    {
      L_ERR("ll2escaped failed for %s", domain);
      return;
    }
  strcpy(ifo->ifname, ifname);
  ifo->ifindex = if_nametoindex(ifname);
  list_add(&ifo->lh, &interfaces);
}
