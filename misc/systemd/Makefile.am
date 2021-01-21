-include $(top_builddir)/common.mk

EXTRA_DIST = voluta-mountd.service.in
CLEANFILES = voluta-mountd.service

volutamountdunitdir = $(prefix)/lib/systemd/system
dist_volutamountdunit_DATA = voluta-mountd.service

voluta-mountd.service: voluta-mountd.service.in
