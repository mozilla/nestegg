## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign 1.7 dist-zip dist-bzip2


SUBDIRS = m4 src include docs test


# we include the whole debian/ dir in EXTRA_DIST because there's a problem
# with autotools and HFS+ MacOSX file systems that caused debian/Makefile.am
# to pick up on the lowercase changelog file and add ChangeLog to DIST_COMMON
# because of it, breaking make dist.  This works just as well.
EXTRA_DIST = \
	README CHANGES COPYING LICENSE \
	autogen.sh \
	nestegg-uninstalled.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nestegg.pc

# Remove the .git folders included in the tarball
dist-hook:
	find $(distdir) -type d -name '.git' | xargs rm -rf

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
