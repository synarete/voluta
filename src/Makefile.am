-include $(top_builddir)/common.mk

noinst_LIBRARIES = libvoluta_prog.a
libvoluta_prog_a_CPPFLAGS = -I$(top_srcdir)/include
libvoluta_prog_a_SOURCES = $(NULL)
libvoluta_prog_a_SOURCES += archive.c
libvoluta_prog_a_SOURCES += clone.c
libvoluta_prog_a_SOURCES += common.c
libvoluta_prog_a_SOURCES += fsck.c
libvoluta_prog_a_SOURCES += getpass.c
libvoluta_prog_a_SOURCES += mkfs.c
libvoluta_prog_a_SOURCES += mntconf.c
libvoluta_prog_a_SOURCES += mount.c
libvoluta_prog_a_SOURCES += query.c
libvoluta_prog_a_SOURCES += restore.c
libvoluta_prog_a_SOURCES += voluta-prog.h
libvoluta_prog_a_SOURCES += show.c
libvoluta_prog_a_SOURCES += umount.c

bin_PROGRAMS = voluta
voluta_CPPFLAGS = -I$(top_srcdir)/include
voluta_LDFLAGS = $(NULL)
voluta_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
voluta_LDFLAGS += -L$(top_builddir)/lib/
voluta_LDFLAGS += -L$(builddir)
voluta_LDFLAGS += -static
voluta_LDADD = @LIBS@
voluta_LDADD += libvoluta_prog.a
voluta_LDADD += $(top_builddir)/lib/libvoluta.la
voluta_LDADD += $(PTHREAD_LIBS)
voluta_LDADD += $(LIBGCRYPT_LIBS)
voluta_SOURCES = main.c

sbin_PROGRAMS = voluta-mountd
voluta_mountd_CPPFLAGS = $(voluta_CPPFLAGS)
voluta_mountd_LDFLAGS = $(voluta_LDFLAGS)
voluta_mountd_LDADD = $(voluta_LDADD)
voluta_mountd_SOURCES = mountd.c

EXTRA_DIST = mountd.conf.in
CLEANFILES = $(voluta_mountd_conf_DATA)
voluta_mountd_confdir = $(sysconfdir)/voluta
voluta_mountd_conf_DATA = mountd.conf

mountd.conf: mountd.conf.in
