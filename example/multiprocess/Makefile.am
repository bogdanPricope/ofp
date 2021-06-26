include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = multiprocess
multiprocess_LDFLAGS = $(AM_LDFLAGS) -static

dist_multiprocess_SOURCES = \
multiprocess_main.c \
../common/cli_arg_parse.c

noinst_HEADERS = \
../common/cli_arg_parse.h

#		${srcdir}/multiprocess.h
