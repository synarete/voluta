-include $(top_builddir)/common.mk

sbin_PROGRAMS = voluta-mountd
voluta_mountd_CPPFLAGS = -I$(top_srcdir)/include
voluta_mountd_LDFLAGS = $(NULL)
voluta_mountd_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
voluta_mountd_LDFLAGS += -L$(builddir)
voluta_mountd_LDFLAGS += -L$(top_builddir)/src/fs
voluta_mountd_LDFLAGS += -L$(top_builddir)/src/infra
voluta_mountd_LDFLAGS += -static
voluta_mountd_LDADD = @LIBS@
voluta_mountd_LDADD += $(top_builddir)/src/fs/libvoluta_fs.la
voluta_mountd_LDADD += $(top_builddir)/src/infra/libvoluta_infra.la
voluta_mountd_LDADD += $(PTHREAD_LIBS)
voluta_mountd_LDADD += $(LIBGCRYPT_LIBS)

voluta_mountd_SOURCES = $(NULL)
voluta_mountd_SOURCES += mntconf.c
voluta_mountd_SOURCES += mountd.c

EXTRA_DIST = mountd.conf.in
CLEANFILES = $(voluta_mountd_conf_DATA)
voluta_mountd_confdir = $(sysconfdir)/voluta
voluta_mountd_conf_DATA = mountd.conf

mountd.conf: mountd.conf.in
