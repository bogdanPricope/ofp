include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = classifier 
classifier_LDFLAGS = $(AM_LDFLAGS) -static

dist_classifier_SOURCES = classifier_main.c \
			  ../common/linux_sigaction.c \
			  ../common/cli_arg_parse.c

noinst_HEADERS = ../common/linux_sigaction.h \
		 ../common/cli_arg_parse.h
