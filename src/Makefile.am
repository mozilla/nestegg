INCLUDES = -I$(top_srcdir)/include -I. -I$(top_srcdir)/halloc

AM_CFLAGS = -ansi -pedantic -Wall -Wextra -Wno-long-long
AM_CFLAGS += -O0 -g
#AM_CFLAGS += -Wstrict-prototypes -Wpointer-arith -Wshadow -Wcast-qual -Wmissing-prototypes
#AM_CFLAGS += -Wstrict-overflow=5 -Wredundant-decls -Wreturn-type


lib_LTLIBRARIES = libnestegg.la

libnestegg_la_SOURCES = \
	nestegg.c \
	$(top_srcdir)/halloc/src/halloc.c \
	$(top_srcdir)/halloc/halloc.h \
	$(top_srcdir)/halloc/src/align.h \
	$(top_srcdir)/halloc/src/hlist.h \
	$(top_srcdir)/halloc/src/macros.h


#libnestegg_la_LDFLAGS = -version-info @SHARED_VERSION_INFO@ @SHLIB_VERSION_ARG@ 
#libnestegg_la_LIBADD = @VPX_LIBS@

