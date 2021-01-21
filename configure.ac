dnl SPDX-License-Identifier: GPL-3.0-or-later
m4_define(VOLUTA_VERSION, m4_esyscmd([./version.sh --version]))
AC_PREREQ([2.69])
AC_INIT([voluta], VOLUTA_VERSION, [synarete@xxxxxx])
AC_COPYRIGHT([Copyright (C) 2020, Shachar Sharon])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([lib/super.c])
AX_VOLUTA_GLOBALS(voluta)
AX_CHECK_ENABLE_DEBUG(no, DEBUG)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_ARG_PROGRAM
AC_PRESERVE_HELP_ORDER
AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([1.11 -Wall -Werror -Wno-portability
                  foreign silent-rules subdir-objects tar-pax])
dnl AM_MAINTAINER_MODE
AM_SILENT_RULES
AC_LANG([C])
AC_SUBST(AR_FLAGS, [cr])

dnl Package needs & wants; defined buy m4 sub-macros (order is important!)
AX_VOLUTA_HAVE_ARGS
AX_VOLUTA_WANT_PROGS
AX_VOLUTA_WANT_CC
AX_VOLUTA_WANT_PYTHON
AX_VOLUTA_NEED_CONFIG_H
AX_VOLUTA_NEED_PROGS
AX_VOLUTA_NEED_TYPES
AX_VOLUTA_NEED_EXTRA_TYPES
AX_VOLUTA_NEED_HEADERS
AX_VOLUTA_NEED_LIBS
AX_VOLUTA_NEED_FUNCS
AX_VOLUTA_NEED_BUILTIN

dnl Libtool
LT_PREREQ([2.2])
LT_INIT

dnl Generate output:
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_FILES([common.mk])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([include/Makefile])
AC_CONFIG_FILES([lib/Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_CONFIG_FILES([doc/man/Makefile])
AC_CONFIG_FILES([doc/html/Makefile])
AC_CONFIG_FILES([misc/Makefile])
AC_CONFIG_FILES([misc/completions/Makefile])
AC_CONFIG_FILES([misc/systemd/Makefile])
AC_CONFIG_FILES([test/Makefile])
AC_CONFIG_FILES([test/dstress/Makefile])
AC_CONFIG_FILES([test/unitest/Makefile])
AC_CONFIG_FILES([test/vfstest/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([Package........: $pkg_name])
AC_MSG_NOTICE([Version........: $pkg_version])
AC_MSG_NOTICE([Release........: $pkg_release])
AC_MSG_NOTICE([Revision.......: $pkg_revision])
AC_MSG_NOTICE([Prefix.........: $prefix])
AC_MSG_NOTICE([Host...........: $host])
AC_MSG_NOTICE([Build..........: $build])
AC_MSG_NOTICE([Compiler.......: $CC])
