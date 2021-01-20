include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = mcast

mcast_LDFLAGS = $(AM_LDFLAGS) -static

dist_mcast_SOURCES = app_main.c mcast.c \
		     ../common/linux_sigaction.c \
		     ../common/linux_resources.c

noinst_HEADERS = ${srcdir}/mcast.h \
		 ../common/linux_sigaction.h \
		 ../common/linux_resources.h
