include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ioctl_test

ioctl_test_LDFLAGS = $(AM_LDFLAGS) -static

dist_ioctl_test_SOURCES = app_main.c ioctl_test.c \
			  ../common/linux_resources.c

noinst_HEADERS = ${srcdir}/ioctl_test.h \
		 ../common/linux_resources.h
