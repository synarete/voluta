-include $(top_builddir)/common.mk

dist_sbin_SCRIPTS = $(NULL)
dist_sbin_SCRIPTS += fsck.voluta
dist_sbin_SCRIPTS += mkfs.voluta
dist_sbin_SCRIPTS += mount.voluta

bin_PROGRAMS = voluta
voluta_CPPFLAGS = -I$(top_srcdir)/include
voluta_LDFLAGS = $(NULL)
voluta_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
voluta_LDFLAGS += -L$(builddir)
voluta_LDFLAGS += -L$(top_builddir)/src/fs
voluta_LDFLAGS += -L$(top_builddir)/src/infra
voluta_LDFLAGS += -static
voluta_LDADD = @LIBS@
voluta_LDADD += $(top_builddir)/src/fs/libvoluta_fs.la
voluta_LDADD += $(top_builddir)/src/infra/libvoluta_infra.la
voluta_LDADD += $(PTHREAD_LIBS)
voluta_LDADD += $(LIBGCRYPT_LIBS)
voluta_SOURCES = $(NULL)
voluta_SOURCES += clone.c
voluta_SOURCES += common.c
voluta_SOURCES += fsck.c
voluta_SOURCES += getpass.c
voluta_SOURCES += main.c
voluta_SOURCES += mkfs.c
voluta_SOURCES += mount.c
voluta_SOURCES += show.c
voluta_SOURCES += umount.c
voluta_SOURCES += voluta-cmd.h

