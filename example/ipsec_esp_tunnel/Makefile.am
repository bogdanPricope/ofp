include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ipsec_esp_tunnel 
ipsec_esp_tunnel_LDFLAGS = $(AM_LDFLAGS) -static

dist_ipsec_esp_tunnel_SOURCES = app_main.c \
	 ../common/linux_sigaction.c

noinst_HEADERS = ../common/linux_sigaction.h
