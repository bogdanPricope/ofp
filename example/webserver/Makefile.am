include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = webserver

webserver_LDFLAGS = $(AM_LDFLAGS) -static

dist_webserver_SOURCES = app_main.c httpd.c \
			 ../common/linux_sigaction.c \
			 ../common/linux_resources.c \
			../common/cli_arg_parse.c

noinst_HEADERS = ${srcdir}/httpd.h \
		 ../common/linux_sigaction.h \
		 ../common/linux_resources.h \
		 ../common/cli_arg_parse.h
