AC_DEFUN([AX_VOLUTA_NEED_CONFIG_H],
[
  AC_DEFINE_UNQUOTED([VERSION_MAJOR], [$pkg_version_major])
  AH_TEMPLATE([VERSION_MAJOR], [Version major number])

  AC_DEFINE_UNQUOTED([VERSION_MINOR], [$pkg_version_minor])
  AH_TEMPLATE([VERSION_MINOR], [Version minor number])

  AC_DEFINE_UNQUOTED([VERSION_SUBLEVEL], [$pkg_version_sublevel])
  AH_TEMPLATE([VERSION_SUBLEVEL], [Version sublevel number])

  AC_DEFINE_UNQUOTED([RELEASE], ["$pkg_release"])
  AH_TEMPLATE([RELEASE], [Release number])

  AC_DEFINE_UNQUOTED([REVISION], ["$pkg_revision"])
  AH_TEMPLATE([REVISION], [Revision id])
])
