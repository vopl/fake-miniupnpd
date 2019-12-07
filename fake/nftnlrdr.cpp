extern "C"
{
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <net/if.h>

#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "config.h"
#include "commonrdr.h"

}
#include <cassert>
#include "records.hpp"
#include <vector>

/* init and shutdown functions */
extern "C" int
init_redirect(void)
{
    return 0;
}

extern "C" extern "C" void
shutdown_redirect(void)
{
}

extern "C" extern "C" int
set_rdr_name(rdr_name_type param, const char *string)
{
    return 0;
}

extern "C" int
add_redirect_rule2(const char * ifname,
		   const char * rhost, unsigned short eport,
		   const char * iaddr, unsigned short iport, int proto,
		   const char * desc, unsigned int timestamp)
{
    Record *pr{};
    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            pr = &r;
            break;;
        }
    }

    if(!pr)
    {
        _records.push_back(Record{});
        pr = &_records.back();
    }

    *pr = Record{};

    pr->_uid = 0;
    if(ifname)  pr->_ifname = ifname;
    if(rhost)   pr->_rhost = rhost;
                pr->_eport = eport;
    if(iaddr)   pr->_ihost = iaddr;
                pr->_iport = iport;
                pr->_proto = proto;
    if(desc)    pr->_desc = desc;
                pr->_timestamp = timestamp;

    return 0;
}

/*
 * This function submit the rule as following:
 * nft add rule nat miniupnpd-pcp-peer ip
 *    saddr <iaddr> ip daddr <rhost> tcp sport <iport>
 *    tcp dport <rport> snat <eaddr>:<eport>
 */
extern "C" int
add_peer_redirect_rule2(const char * ifname,
			const char * rhost, unsigned short rport,
			const char * eaddr, unsigned short eport,
			const char * iaddr, unsigned short iport, int proto,
			const char * desc, unsigned int timestamp)
{
    Record *pr{};
    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            pr = &r;
            break;;
        }
    }

    if(!pr)
    {
        _records.push_back(Record{});
        pr = &_records.back();
    }

    *pr = Record{};

    pr->_uid = 0;
    if(ifname)  pr->_ifname = ifname;
    if(rhost)   pr->_rhost = rhost;
                pr->_rport = rport;
    if(eaddr)   pr->_ehost = eaddr;
                pr->_eport = eport;
    if(iaddr)   pr->_ihost = iaddr;
                pr->_iport = iport;
                pr->_proto = proto;
    if(desc)    pr->_desc = desc;
                pr->_timestamp = timestamp;

    return 0;
}

/*
 * This function submit the rule as following:
 * nft add rule filter miniupnpd
 *    ip daddr <iaddr> tcp dport <iport> accept
 *
 */
extern "C" int
add_filter_rule2(const char * ifname,
		 const char * rhost, const char * iaddr,
		 unsigned short eport, unsigned short iport,
		 int proto, const char * desc)
{
    return 0;
}

extern "C" int
delete_filter_rule(const char * ifname, unsigned short port, int proto)
{
    return 0;
}

/*
 * Clear all rules corresponding eport/proto
 */
extern "C" int
delete_redirect_and_filter_rules(unsigned short eport, int proto)
{
    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }

        if(eport)   if(r._eport != eport) continue;
        if(proto)   if(r._proto != proto) continue;

        r._uid = -1;

        return 0;
    }

    return -1;
}

/*
 * get peer by index as array.
 * return -1 when not found.
 */
extern "C" int
get_peer_rule_by_index(int index,
		       char * ifname, unsigned short * eport,
		       char * iaddr, int iaddrlen, unsigned short * iport,
		       int * proto, char * desc, int desclen,
		       char * rhost, int rhostlen, unsigned short * rport,
		       unsigned int * timestamp,
		       u_int64_t * packets, u_int64_t * bytes)
{
    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }
        if(index)
        {
            --index;
            continue;
        }

        if(ifname)      strcpy(ifname, r._ifname.data());
        if(eport)       *eport = r._eport;
        if(proto)       *proto = r._proto;

        if(rhost)       strncpy(rhost, r._rhost.data(), rhostlen);
        if(rport)       *rport = r._rport;
        if(iaddr)       strncpy(iaddr, r._ihost.data(), iaddrlen);
        if(iport)       *iport = r._iport;
        if(desc)        strncpy(desc, r._desc.data(), desclen);
        if(timestamp)   *timestamp = r._timestamp;

        if(packets)     *packets = 220;
        if(bytes)       *bytes = 380;

        return 0;
    }

    return -1;
}

/*
 * get_redirect_rule()
 * returns -1 if the rule is not found
 */
extern "C" int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
		  char * iaddr, int iaddrlen, unsigned short * iport,
		  char * desc, int desclen,
		  char * rhost, int rhostlen,
		  unsigned int * timestamp,
		  u_int64_t * packets, u_int64_t * bytes)
{
    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }

        if(ifname)  if(r._ifname != ifname) continue;
        if(eport)   if(r._eport != eport) continue;
        if(proto)   if(r._proto != proto) continue;

        if(rhost)       strncpy(rhost, r._rhost.data(), rhostlen);
        if(iaddr)       strncpy(iaddr, r._ihost.data(), iaddrlen);
        if(iport)       *iport = r._iport;
        if(desc)        strncpy(desc, r._desc.data(), desclen);
        if(timestamp)   *timestamp = r._timestamp;

        if(packets)     *packets = 220;
        if(bytes)       *bytes = 380;

        return 0;
    }

    return -1;
}

/*
 * get_redirect_rule_by_index()
 * return -1 when the rule was not found
 */
extern "C" int
get_redirect_rule_by_index(int index,
			   char * ifname, unsigned short * eport,
			   char * iaddr, int iaddrlen, unsigned short * iport,
			   int * proto, char * desc, int desclen,
			   char * rhost, int rhostlen,
			   unsigned int * timestamp,
			   u_int64_t * packets, u_int64_t * bytes)
{
    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }
        if(index)
        {
            --index;
            continue;
        }

        if(ifname)      strcpy(ifname, r._ifname.data());
        if(eport)       *eport = r._eport;
        if(proto)       *proto = r._proto;

        if(rhost)       strncpy(rhost, r._rhost.data(), rhostlen);
        if(iaddr)       strncpy(iaddr, r._ihost.data(), iaddrlen);
        if(iport)       *iport = r._iport;
        if(desc)        strncpy(desc, r._desc.data(), desclen);
        if(timestamp)   *timestamp = r._timestamp;

        if(packets)     *packets = 220;
        if(bytes)       *bytes = 380;

        return 0;
    }

    return -1; /* not found */
}

/*
 * return -1 not found.
 * return 0 found
 */
extern "C" int
get_nat_redirect_rule(const char * nat_chain_name, const char * ifname,
		      unsigned short eport, int proto,
		      char * iaddr, int iaddrlen, unsigned short * iport,
		      char * desc, int desclen,
		      char * rhost, int rhostlen,
		      unsigned int * timestamp,
		      u_int64_t * packets, u_int64_t * bytes)
{
    (void)nat_chain_name;

    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }

        if(ifname)  if(r._ifname != ifname) continue;
        if(eport)   if(r._eport != eport) continue;
        if(proto)   if(r._proto != proto) continue;

        if(rhost)       strncpy(rhost, r._rhost.data(), rhostlen);
        if(iaddr)       strncpy(iaddr, r._ihost.data(), iaddrlen);
        if(iport)       *iport = r._iport;
        if(desc)        strncpy(desc, r._desc.data(), desclen);
        if(timestamp)   *timestamp = r._timestamp;

        if(packets)     *packets = 220;
        if(bytes)       *bytes = 380;

        return 0;
    }

    return -1;
}

/*
 * return an (malloc'ed) array of "external" port for which there is
 * a port mapping. number is the size of the array
 */
unsigned short *
get_portmappings_in_range(unsigned short startport, unsigned short endport,
			  int proto, unsigned int * number)
{
    std::vector<unsigned short> eports;
    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }

                    if(r._eport < startport || r._eport > endport) continue;
        if(proto)   if(r._proto != proto) continue;

        eports.push_back(r._eport);
    }

    if(number) *number = eports.size();

    unsigned short *res = (unsigned short *)malloc(eports.size() * sizeof(unsigned short));
    memcpy(res, eports.data(), eports.size() * sizeof(unsigned short));
    return res;
}

int
update_portmapping_desc_timestamp(const char * ifname,
                   unsigned short eport, int proto,
                   const char * desc, unsigned int timestamp)
{
    int res = -1;

    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }

        if(ifname)  if(r._ifname != ifname) continue;
        if(eport)   if(r._eport != eport) continue;
        if(proto)   if(r._proto != proto) continue;
        if(desc)    if(r._desc != desc) continue;

        r._timestamp = timestamp;

        res = 0;
    }

    return res;
}

int
update_portmapping(const char * ifname, unsigned short eport, int proto,
                   unsigned short iport, const char * desc,
                   unsigned int timestamp)
{
    int res = -1;

    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }

        if(ifname)  if(r._ifname != ifname) continue;
        if(eport)   if(r._eport != eport) continue;
        if(iport)   if(r._iport != iport) continue;
        if(proto)   if(r._proto != proto) continue;
        if(desc)    if(r._desc != desc) continue;

        r._timestamp = timestamp;

        res = 0;
    }

    return res;
}
