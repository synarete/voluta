-include $(top_builddir)/common.mk

bin_PROGRAMS = voluta-unitest
voluta_unitest_CPPFLAGS = $(NULL)
voluta_unitest_CPPFLAGS += -I$(top_srcdir)/include
voluta_unitest_CPPFLAGS += -I$(top_srcdir)/lib
voluta_unitest_CPPFLAGS += -DVOLUTA_UNITEST=1
voluta_unitest_LDFLAGS = $(NULL)
voluta_unitest_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
voluta_unitest_LDFLAGS += -L$(top_builddir)/lib/
voluta_unitest_LDFLAGS += -static
voluta_unitest_LDADD = $(NULL)
voluta_unitest_LDADD += @LIBS@
voluta_unitest_LDADD += $(top_builddir)/lib/libvoluta.la
voluta_unitest_LDADD += $(PTHREAD_LIBS)
voluta_unitest_LDADD += $(LIBGCRYPT_LIBS)
voluta_unitest_SOURCES = $(NULL)
voluta_unitest_SOURCES += unitest.h
voluta_unitest_SOURCES += unitest_main.c
voluta_unitest_SOURCES += unitest_exec.c
voluta_unitest_SOURCES += unitest_ops.c
voluta_unitest_SOURCES += ut_alloc.c
voluta_unitest_SOURCES += ut_archive.c
voluta_unitest_SOURCES += ut_avl.c
voluta_unitest_SOURCES += ut_dir_basic.c
voluta_unitest_SOURCES += ut_dir_iter.c
voluta_unitest_SOURCES += ut_dir_list.c
voluta_unitest_SOURCES += ut_file_basic.c
voluta_unitest_SOURCES += ut_file_edges.c
voluta_unitest_SOURCES += ut_file_falloc.c
voluta_unitest_SOURCES += ut_file_fiemap.c
voluta_unitest_SOURCES += ut_file_lseek.c
voluta_unitest_SOURCES += ut_file_random.c
voluta_unitest_SOURCES += ut_file_ranges.c
voluta_unitest_SOURCES += ut_file_records.c
voluta_unitest_SOURCES += ut_file_stat.c
voluta_unitest_SOURCES += ut_file_trunc.c
voluta_unitest_SOURCES += ut_fillfs.c
voluta_unitest_SOURCES += ut_ioctl.c
voluta_unitest_SOURCES += ut_namei.c
voluta_unitest_SOURCES += ut_reload.c
voluta_unitest_SOURCES += ut_rename.c
voluta_unitest_SOURCES += ut_strings.c
voluta_unitest_SOURCES += ut_super.c
voluta_unitest_SOURCES += ut_symlink.c
voluta_unitest_SOURCES += ut_xattr.c


if VOLUTA_RUN_UNITESTS
ut_check_dir := "$(builddir)/ut"

all-local:
	@mkdir -p $(ut_check_dir)

clean-local:
	@rm -rf $(ut_check_dir)

check-local: $(bin_PROGRAMS)
	@mkdir -p $(ut_check_dir)
	@echo "  TEST       " && $$(realpath "$^") $(ut_check_dir) ;
	@rm -rf $(ut_check_dir)

endif
