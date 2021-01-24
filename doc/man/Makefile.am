-include $(top_builddir)/common.mk

EXTRA_DIST = $(NULL)
EXTRA_DIST += voluta.1.rst
EXTRA_DIST += voluta-mountd.8.rst

if HAVE_RST2MAN
dist_man_MANS = $(NULL)
dist_man_MANS += voluta.1
dist_man_MANS += voluta-mountd.8
CLEANFILES = $(dist_man_MANS)

all-local: $(dist_man_MANS)

dist-local: all-local


rst2man = @RST2MAN@

%.1: %.1.rst
	@echo "  RST2MAN  $@" && $(rst2man) < $< > $@ ;

%.8: %.8.rst
	@echo "  RST2MAN  $@" && $(rst2man) < $< > $@ ;

endif


