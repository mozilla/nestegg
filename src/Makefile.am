INCLUDES = -I$(top_srcdir)/include -I. -I./halloc

AM_CFLAGS = -ansi -pedantic -Wall -Wextra -Wno-long-long
AM_CFLAGS += -O0 -g
#AM_CFLAGS += -Wstrict-prototypes -Wpointer-arith -Wshadow -Wcast-qual -Wmissing-prototypes
#AM_CFLAGS += -Wstrict-overflow=5 -Wredundant-decls -Wreturn-type


lib_LTLIBRARIES = libnestegg.la

libnestegg_la_SOURCES = \
	nestegg.c \
	halloc/src/halloc.c \
	halloc/halloc.h \
	halloc/src/align.h \
	halloc/src/hlist.h \
	halloc/src/macros.h


#libnestegg_la_LDFLAGS = -version-info @SHARED_VERSION_INFO@ @SHLIB_VERSION_ARG@ 
#libnestegg_la_LIBADD = @VPX_LIBS@

