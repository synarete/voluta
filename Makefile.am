ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
SUBDIRS = . include src test doc misc

EXTRA_DIST = $(NULL)
EXTRA_DIST += version.sh
EXTRA_DIST += README.md
EXTRA_DIST += TODO
EXTRA_DIST += VERSION
EXTRA_DIST += REVISION
EXTRA_DIST += COPYING
EXTRA_DIST += common.mk.in

BUILT_SOURCES = REVISION
CLEANFILES = REVISION

REVISION:
	@$(top_srcdir)/version.sh --revision > $@
	@echo >> $@







