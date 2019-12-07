
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
#include <limits.h>

#include "upnputils.h"
//#include "nftpinhole.h"

#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "config.h"
}

#include <cassert>
#include "records.hpp"

/////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
extern "C" void init_iptpinhole(void)
{
	return;
}

extern "C" void shutdown_iptpinhole(void)
{
    for(Record &r : _records)
    {
        r._uid = -1;
    }
}

/*
ip saddr <rem_host> ip daddr <int_client> tcp sport <rem_port>  tcp dport <int_port>
*/
extern "C" int add_pinhole(const char * ifname,
                const char * rem_host, unsigned short rem_port,
                const char * int_client, unsigned short int_port,
                int proto, const char * desc, unsigned int timestamp)
{
    Record *r{};
    for(int idx{}; idx<_records.size(); ++idx)
    {
        if(-1 == _records[idx]._uid)
        {
            r = &_records[idx];
            r->_uid = idx+1;
            break;
        }
    }

    if(!r)
    {
        _records.push_back(Record{});
        r = &_records.back();
        r->_uid = _records.size();
    }

    if(ifname)      r->_ifname = ifname;
    if(rem_host)    r->_rhost = rem_host;
                    r->_rport = rem_port;
    if(int_client)  r->_ihost = int_client;
                    r->_iport = int_port;
                    r->_proto = proto;
    if(desc)        r->_desc = desc;
                    r->_timestamp = timestamp;

    return r->_uid;
}

extern "C" int
find_pinhole(const char * ifname,
             const char * rem_host, unsigned short rem_port,
             const char * int_client, unsigned short int_port,
             int proto,
             char *desc, int desc_len, unsigned int * timestamp)
{
    for(const Record &r : _records)
    {
        if(r._uid <= 0)
        {
            continue;
        }

        if(ifname)      if(r._ifname != ifname) continue;
        if(rem_host)    if(r._rhost != rem_host) continue;
                        if(r._rport != rem_port) continue;
        if(int_client)  if(r._ihost != int_client) continue;
                        if(r._iport != int_port) continue;
                        if(r._proto != proto) continue;

        if(desc)        strncpy(desc, r._desc.data(), desc_len);
        if(timestamp)   *timestamp = r._timestamp;

        return r._uid;
    }

    return -2; /* not found */
}

extern "C" int
delete_pinhole(unsigned short uid)
{
    for(Record &r : _records)
    {
        if(r._uid == uid)
        {
            r._uid = -1;
            return 0;
        }
    }

    return -2; /* not found */
}

extern "C" int
update_pinhole(unsigned short uid, unsigned int timestamp)
{
    for(Record &r : _records)
    {
        if(r._uid == uid)
        {
            r._timestamp = timestamp;
            return 0;
        }
    }

    return -2; /* not found */
}

extern "C" int
get_pinhole_info(unsigned short uid,
                 char * rem_host, int rem_hostlen,
                 unsigned short * rem_port,
                 char * int_client, int int_clientlen,
                 unsigned short * int_port,
                 int * proto, char * desc, int desclen,
                 unsigned int * timestamp,
                 u_int64_t * packets, u_int64_t * bytes)
{
    for(Record &r : _records)
    {
        if(r._uid == uid)
        {
            if(rem_host)    strncpy(rem_host, r._rhost.data(), rem_hostlen);
            if(rem_port)    *rem_port = r._rport;
            if(int_client)  strncpy(int_client, r._ihost.data(), int_clientlen);
            if(int_port)    *int_port = r._iport;
            if(proto)       *proto = r._proto;
            if(desc)        strncpy(desc, r._desc.data(), desclen);
            if(timestamp)   *timestamp = r._timestamp;

            if(packets)     *packets = 220;
            if(bytes)       *bytes = 380;

            return 0;
        }
    }

    return -2; /* not found */
}

extern "C" int get_pinhole_uid_by_index(int index)
{
    for(Record &r : _records)
    {
        if(r._uid <= 0)
        {
            continue;
        }
        if(!index)
        {
            return r._uid;
        }
        --index;
    }

    return -2; /* not found */
}

extern "C" int
clean_pinhole_list(unsigned int * next_timestamp)
{
    unsigned int min_ts = UINT_MAX;
    int n = 0;
    time_t current_time = upnp_time();

    for(Record &r : _records)
    {
        if(r._uid <= 0)
        {
            continue;
        }

        if(r._timestamp <= (unsigned int)current_time)
        {
            r._uid = -1;
            n++;
        }
        else
        {
            if (r._timestamp < min_ts)
            {
                min_ts = r._timestamp;
            }
        }
    }

    if(next_timestamp && (min_ts != UINT_MAX))
    {
        *next_timestamp = min_ts;
    }

    return n;
}
