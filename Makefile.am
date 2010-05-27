## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign 1.11 no-dist-gzip dist-bzip2 subdir-objects
ACLOCAL_AMFLAGS = -Im4

INCLUDES = -I$(top_srcdir)/include -I. -I$(top_srcdir)/halloc
AM_CFLAGS = -ansi -pedantic -Wall -Wextra -Wno-long-long -O0 -g

SUBDIRS = docs


# we include the whole debian/ dir in EXTRA_DIST because there's a problem
# with autotools and HFS+ MacOSX file systems that caused debian/Makefile.am
# to pick up on the lowercase changelog file and add ChangeLog to DIST_COMMON
# because of it, breaking make dist.  This works just as well.
EXTRA_DIST = \
	AUTHORS README LICENSE \
	nestegg-uninstalled.pc.in \
	m4/as-ac-expand.m4 \
	m4/pkg.m4 \
	m4/ax_create_stdint_h.m4 \
	halloc/src/halloc.c \
	halloc/halloc.h \
	halloc/src/align.h \
	halloc/src/hlist.h \
	halloc/src/macros.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nestegg.pc

nesteggincludedir = $(includedir)/nestegg
nestegginclude_HEADERS = include/nestegg/nestegg.h

lib_LTLIBRARIES = src/libnestegg.la

src_libnestegg_la_SOURCES = \
	src/nestegg.c \
	halloc/src/halloc.c \
	halloc/halloc.h \
	halloc/src/align.h \
	halloc/src/hlist.h \
	halloc/src/macros.h

check_PROGRAMS = test/test

test_test_SOURCES = test/test.c
test_test_LDADD = src/libnestegg.la

DISTCLEANFILES = _stdint.h

# Remove the .git folders included in the tarball
dist-hook:
	find $(distdir) -type d -name '.git' | xargs rm -rf

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
