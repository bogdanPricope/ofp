include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = fpm
fpm_LDFLAGS = $(AM_LDFLAGS) -static

dist_fpm_SOURCES = app_main.c \
	 ../common/linux_sigaction.c\
	 ../common/cli_arg_parse.c

noinst_HEADERS = ../common/linux_sigaction.h\
		 ../common/cli_arg_parse.h
