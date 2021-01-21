AC_DEFUN([AX_VOLUTA_HAVE_ARGS],
[
  AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debug mode]))

  AS_IF([test "x$enable_debug" = "xyes"], [AC_MSG_NOTICE([Debug mode])])
])


