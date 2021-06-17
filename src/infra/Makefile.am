-include $(top_builddir)/common.mk

libvoluta_infradir = $(libdir)
libvoluta_infra_LTLIBRARIES = libvoluta_infra.la
libvoluta_infra_la_LDFLAGS = $(NULL)
libvoluta_infra_la_LDFLAGS += $(PTHREAD_CFLAGS) $(PTHREAD_DEF)
libvoluta_infra_la_LDFLAGS += -version-info 0
libvoluta_infra_la_CPPFLAGS = $(NULL)
libvoluta_infra_la_CPPFLAGS += -I$(top_srcdir)/include
libvoluta_infra_la_CPPFLAGS += -DVOLUTA_USE_PRIVATE=1
libvoluta_infra_la_LIBADD = @LIBS@
libvoluta_infra_la_LIBADD += $(PTHREAD_LIBS)
libvoluta_infra_la_SOURCES = $(NULL)
libvoluta_infra_la_SOURCES += avl.c
libvoluta_infra_la_SOURCES += fiovec.c
libvoluta_infra_la_SOURCES += list.c
libvoluta_infra_la_SOURCES += logging.c
libvoluta_infra_la_SOURCES += panic.c
libvoluta_infra_la_SOURCES += pipe.c
libvoluta_infra_la_SOURCES += qalloc.c
libvoluta_infra_la_SOURCES += random.c
libvoluta_infra_la_SOURCES += slice.c
libvoluta_infra_la_SOURCES += socket.c
libvoluta_infra_la_SOURCES += strings.c
libvoluta_infra_la_SOURCES += syscall.c
libvoluta_infra_la_SOURCES += syscallx.c
libvoluta_infra_la_SOURCES += thread.c
libvoluta_infra_la_SOURCES += time.c
libvoluta_infra_la_SOURCES += utility.c
libvoluta_infra_la_SOURCES += version.c
