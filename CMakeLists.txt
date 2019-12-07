#./fake-miniupnpd -d -a lo -i lo -o 1.2.3.4 -N -A "allow 1024-65535 0.0.0.0/0 1024-65535"

cmake_minimum_required(VERSION 2.8)

project(fake-miniupnpd)

add_definitions(-D_GNU_SOURCE)

add_executable(fake-miniupnpd

    miniupnp/miniupnpd/asyncsendto.c
    miniupnp/miniupnpd/daemonize.c
    miniupnp/miniupnpd/getconnstatus.c
    miniupnp/miniupnpd/getifaddr.c
    miniupnp/miniupnpd/minissdp.c
    miniupnp/miniupnpd/miniupnpd.c
#    miniupnp/miniupnpd/miniupnpdctl.c
    miniupnp/miniupnpd/minixml.c
    miniupnp/miniupnpd/natpmp.c
    miniupnp/miniupnpd/options.c
    miniupnp/miniupnpd/pcplearndscp.c
    miniupnp/miniupnpd/pcpserver.c
    miniupnp/miniupnpd/portinuse.c
    miniupnp/miniupnpd/upnpdescgen.c
    miniupnp/miniupnpd/upnpevents.c
    miniupnp/miniupnpd/upnpglobalvars.c
    miniupnp/miniupnpd/upnphttp.c
    miniupnp/miniupnpd/upnppermissions.c
    miniupnp/miniupnpd/upnppinhole.c
    miniupnp/miniupnpd/upnpredirect.c
    miniupnp/miniupnpd/upnpreplyparse.c
    miniupnp/miniupnpd/upnpsoap.c
    miniupnp/miniupnpd/upnpstun.c
    miniupnp/miniupnpd/upnputils.c

    miniupnp/miniupnpd/asyncsendto.h
    miniupnp/miniupnpd/codelength.h
    miniupnp/miniupnpd/commonrdr.h
    miniupnp/miniupnpd/daemonize.h
    miniupnp/miniupnpd/getconnstatus.h
    miniupnp/miniupnpd/getifaddr.h
    miniupnp/miniupnpd/getifstats.h
    miniupnp/miniupnpd/getroute.h
    miniupnp/miniupnpd/ifacewatcher.h
    miniupnp/miniupnpd/macros.h
    miniupnp/miniupnpd/minissdp.h
    miniupnp/miniupnpd/miniupnpdpath.h
    miniupnp/miniupnpd/miniupnpdtypes.h
    miniupnp/miniupnpd/minixml.h
    miniupnp/miniupnpd/natpmp.h
    miniupnp/miniupnpd/options.h
    miniupnp/miniupnpd/pcp_msg_struct.h
    miniupnp/miniupnpd/pcplearndscp.h
    miniupnp/miniupnpd/pcpserver.h
    miniupnp/miniupnpd/portinuse.h
    miniupnp/miniupnpd/upnpdescgen.h
    miniupnp/miniupnpd/upnpdescstrings.h
    miniupnp/miniupnpd/upnpevents.h
    miniupnp/miniupnpd/upnpglobalvars.h
    miniupnp/miniupnpd/upnphttp.h
    miniupnp/miniupnpd/upnppermissions.h
    miniupnp/miniupnpd/upnppinhole.h
    miniupnp/miniupnpd/upnpredirect.h
    miniupnp/miniupnpd/upnpreplyparse.h
    miniupnp/miniupnpd/upnpsoap.h
    miniupnp/miniupnpd/upnpstun.h
    miniupnp/miniupnpd/upnpurns.h
    miniupnp/miniupnpd/upnputils.h

    miniupnp/miniupnpd/linux/getifstats.c
    miniupnp/miniupnpd/linux/getroute.c
    miniupnp/miniupnpd/linux/ifacewatcher.c

    fake/nftables.cpp
    fake/nftpinhole.cpp
    fake/nftnlrdr.cpp
    fake/nfct_get.cpp

    fake/records.hpp
    fake/records.cpp
)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/config.h
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory stub
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/miniupnp/miniupnpd/VERSION VERSION
    COMMAND ${CMAKE_SOURCE_DIR}/miniupnp/miniupnpd/genconfig.sh --ipv6 --debug --leasefile --pcp-peer --portinuse --firewall=nftables
    COMMAND ${CMAKE_COMMAND} -E echo "" >> config.h
    COMMAND ${CMAKE_COMMAND} -E echo "//customs for fake" >> config.h
    COMMAND ${CMAKE_COMMAND} -E echo "#define DISABLE_CONFIG_FILE" >> config.h
    VERBATIM
    DEPENDS ${CMAKE_SOURCE_DIR}/miniupnp/miniupnpd/genconfig.sh ${CMAKE_SOURCE_DIR}/miniupnp/miniupnpd/VERSION)

target_sources(fake-miniupnpd PRIVATE ${CMAKE_BINARY_DIR}/config.h)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_BINARY_DIR}/stub)
include_directories(miniupnp/miniupnpd)
target_link_libraries(fake-miniupnpd uuid)
