-include $(top_builddir)/common.mk

libvoluta_fsdir = $(libdir)
libvoluta_fs_LTLIBRARIES = libvoluta_fs.la
libvoluta_fs_la_LDFLAGS = $(NULL)
libvoluta_fs_la_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
libvoluta_fs_la_LDFLAGS += -version-info 0
libvoluta_fs_la_CPPFLAGS = $(NULL)
libvoluta_fs_la_CPPFLAGS += -I$(top_srcdir)/include
libvoluta_fs_la_CPPFLAGS += -DVOLUTA_LIBPRIVATE=1
libvoluta_fs_la_LIBADD = @LIBS@
libvoluta_fs_la_LIBADD += $(PTHREAD_LIBS)
libvoluta_fs_la_SOURCES = $(NULL)
libvoluta_fs_la_SOURCES += address.c
libvoluta_fs_la_SOURCES += boot.c
libvoluta_fs_la_SOURCES += cache.c
libvoluta_fs_la_SOURCES += crypto.c
libvoluta_fs_la_SOURCES += dir.c
libvoluta_fs_la_SOURCES += exec.c
libvoluta_fs_la_SOURCES += file.c
libvoluta_fs_la_SOURCES += fuseq.c
libvoluta_fs_la_SOURCES += init.c
libvoluta_fs_la_SOURCES += inode.c
libvoluta_fs_la_SOURCES += itable.c
libvoluta_fs_la_SOURCES += mount.c
libvoluta_fs_la_SOURCES += mpool.c
libvoluta_fs_la_SOURCES += namei.c
libvoluta_fs_la_SOURCES += nodes.c
libvoluta_fs_la_SOURCES += opers.c
libvoluta_fs_la_SOURCES += osdc.c
libvoluta_fs_la_SOURCES += spmaps.c
libvoluta_fs_la_SOURCES += super.c
libvoluta_fs_la_SOURCES += symlink.c
libvoluta_fs_la_SOURCES += xattr.c
