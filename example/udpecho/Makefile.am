include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = udpecho

udpecho_LDFLAGS = $(AM_LDFLAGS) -static

dist_udpecho_SOURCES = app_main.c udp_server.c \
		       ../common/linux_sigaction.c

noinst_HEADERS = ${srcdir}/udp_server.h \
		 ../common/linux_sigaction.h
