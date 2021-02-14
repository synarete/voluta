-include $(top_builddir)/common.mk

EXTRA_DIST = $(NULL)
EXTRA_DIST += index.html.in
EXTRA_DIST += voluta.css
EXTRA_DIST += voluta.rst

if HAVE_RST2HTML

dist_doc_DATA = index.html voluta.html
DISTCLEANFILES = $(dist_doc_DATA)

rst2html = @RST2HTML@

all-local: $(HTMLPAGES)

dist-local: all-local

%.html: %.rst
	@echo "  RST2HTML  $@" && \
	  $(rst2html) --stylesheet=$(srcdir)/voluta.css < $< > $@ ;

index.html: index.html.in
	@echo "  SED      $@"; $(PATSUBST) $< > $@ ;

endif


