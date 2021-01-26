LIB   = $(top_builddir)/lib

VPATH = $(srcdir) $(builddir)

lib_LTLIBRARIES = $(LIB)/libofp.la

.PHONY: pkgconfig/libofp.pc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libofp.pc

AM_LDFLAGS += -version-number '$(LIBOFP_VERSION)'

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api
AM_CFLAGS +=  $(VISIBILITY_CFLAGS)

LIBS  += $(OFP_LIBS)

__LIB__libofp_la_SOURCES = \
ofp_global_param_shm.c \
ofp_pkt_processing.c \
ofp_pkt_send_burst.c \
ofp_ifnet.c \
ofp_ifnet_portconf.c \
ofp_avl.c \
ofp_log.c \
ofp_api_cli.c \
ofp_thread_proc.c \
ofp_hash.c \
ofp_init.c \
ofp_subr_hash.c \
ofp_timer.c \
ofp_md5c.c \
ofp_errno.c \
ofp_stat.c \
ofp_hook.c \
ofp_util.c \
ofp_shared_mem.c \
ofp_uma.c \
dbg/ofp_debug.c \
dbg/ofp_debug_pcap.c \
dbg/ofp_debug_print.c \
net/syscalls/ofp_epoll.c \
net/syscalls/ofp_sysctl.c \
net/syscalls/ofp_syscalls.c \
net/syscalls/ofp_sys_socket.c \
net/syscalls/ofp_uipc_sockbuf.c \
net/syscalls/ofp_uipc_socket.c \
net/route/ofp_route.c \
net/domain_inet/ofp_uipc_domain.c \
net/domain_inet/ofp_inet.c \
net/domain_inet/ofp_in_proto.c \
net/ip4net/ofp_in.c \
net/ip4net/ofp_in_pcb.c \
net/ip4net/ofp_in_cksum.c \
net/ip4net/ofp_in_mcast.c \
net/ip4net/ofp_ip_shm.c \
net/ip4net/ofp_ip_init.c \
net/ip4net/ofp_ip.c \
net/ip4net/ofp_ip_reass.c \
net/icmp/ofp_icmp.c \
net/udp/ofp_udp_shm.c \
net/udp/ofp_udp_usrreq.c \
net/tcp/ofp_tcp_shm.c \
net/tcp/ofp_tcp_usrreq.c \
net/tcp/ofp_tcp_subr.c \
net/tcp/ofp_tcp_timer.c \
net/tcp/ofp_tcp_output.c \
net/tcp/ofp_tcp_input.c \
net/tcp/ofp_tcp_sack.c \
net/tcp/ofp_tcp_timewait.c \
net/tcp/ofp_tcp_syncache.c \
net/tcp/ofp_tcp_reass.c \
net/ofp_gre.c \
net/ofp_vxlan.c \
net/igmp/ofp_igmp_shm.c \
net/igmp/ofp_igmp.c \
net/ipsec/ofp_ipsec.c \
net/ipsec/ofp_ipsec_spd.c \
net/ipsec/ofp_ipsec_sad.c

if OFP_USE_LIBCK
__LIB__libofp_la_SOURCES += \
net/arp/ofp_arp_ck.c
else
__LIB__libofp_la_SOURCES += \
net/arp/ofp_arp.c
endif

if OFP_USE_LIBCONFIG
AM_CFLAGS += -DOFP_DEFAULT_CONF_FILE="\"$(sysconfdir)/ofp.conf\""
endif

if OFP_SP
__LIB__libofp_la_SOURCES += \
sp/ofp_sp_shm.c \
sp/ofp_netlink.c \
sp/ofp_netlink_msg.c \
sp/ofp_quagga.c \
sp/ofp_tunthread.c
endif

if OFP_IPv6
__LIB__libofp_la_SOURCES += \
net/domain_inet/ofp_in6_proto.c \
net/ip6net/ofp_in6.c \
net/ip6net/ofp_in6_pcb.c \
net/ip6net/ofp_in6_cksum.c \
net/ip6net/ofp_ip6_shm.c \
net/ip6net/ofp_ip6_init.c \
net/udp/ofp_udp6_usrreq.c \
net/icmp/ofp_icmp6.c \
net/ofp_nd6.c
endif

if OFP_MTRIE
__LIB__libofp_la_SOURCES += \
net/route/ofp_rt_mtrie_lookup.c
else
__LIB__libofp_la_SOURCES += \
net/route/ofp_rt_lookup.c
endif

if OFP_CLI
__LIB__libofp_la_SOURCES += \
cli/ofp_cli.c \
cli/ofp_cli_route.c \
cli/ofp_cli_debug.c \
cli/ofp_cli_log.c \
cli/ofp_cli_arp.c \
cli/ofp_cli_alias.c \
cli/ofp_cli_stat.c \
cli/ofp_cli_ifconfig.c \
cli/ofp_cli_address.c \
cli/ofp_cli_sysctl.c \
cli/ofp_cli_ipsec.c \
cli/ofp_cli_netstat.c \
cli/ofp_cli_shutdown.c
endif
