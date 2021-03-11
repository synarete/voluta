
AC_DEFUN([AX_VOLUTA_CHECK_HEADERS],
[
  AC_CHECK_HEADERS([$1], :,
    AC_MSG_ERROR([Unable to find header $1]))
])

AC_DEFUN([AX_VOLUTA_NEED_HEADERS],
[
  AX_VOLUTA_CHECK_HEADERS([stddef.h])
  AX_VOLUTA_CHECK_HEADERS([stdint.h])
  AX_VOLUTA_CHECK_HEADERS([stdlib.h])
  AX_VOLUTA_CHECK_HEADERS([stdbool.h])
  AX_VOLUTA_CHECK_HEADERS([string.h])
  AX_VOLUTA_CHECK_HEADERS([unistd.h])
  AX_VOLUTA_CHECK_HEADERS([termios.h])
  AX_VOLUTA_CHECK_HEADERS([limits.h])
  AX_VOLUTA_CHECK_HEADERS([math.h])
  AX_VOLUTA_CHECK_HEADERS([ctype.h])
  AX_VOLUTA_CHECK_HEADERS([fcntl.h])
  AX_VOLUTA_CHECK_HEADERS([getopt.h])
  AX_VOLUTA_CHECK_HEADERS([iconv.h])
  AX_VOLUTA_CHECK_HEADERS([endian.h])
  AX_VOLUTA_CHECK_HEADERS([execinfo.h])
  AX_VOLUTA_CHECK_HEADERS([syslog.h])
  AX_VOLUTA_CHECK_HEADERS([pthread.h])
  AX_VOLUTA_CHECK_HEADERS([gcrypt.h])
  AX_VOLUTA_CHECK_HEADERS([libunwind.h])
  AX_VOLUTA_CHECK_HEADERS([uuid/uuid.h])
  AX_VOLUTA_CHECK_HEADERS([attr/attributes.h])
  AX_VOLUTA_CHECK_HEADERS([sys/xattr.h])
  AX_VOLUTA_CHECK_HEADERS([sys/types.h])
  AX_VOLUTA_CHECK_HEADERS([sys/wait.h])
  AX_VOLUTA_CHECK_HEADERS([sys/time.h])
  AX_VOLUTA_CHECK_HEADERS([sys/prctl.h])
  AX_VOLUTA_CHECK_HEADERS([sys/socket.h])
  AX_VOLUTA_CHECK_HEADERS([sys/file.h])
  AX_VOLUTA_CHECK_HEADERS([sys/stat.h])
  AX_VOLUTA_CHECK_HEADERS([sys/statvfs.h])
  AX_VOLUTA_CHECK_HEADERS([sys/vfs.h])
  AX_VOLUTA_CHECK_HEADERS([sys/sysinfo.h])
  AX_VOLUTA_CHECK_HEADERS([sys/resource.h])
  AX_VOLUTA_CHECK_HEADERS([sys/capability.h])
  AX_VOLUTA_CHECK_HEADERS([sys/ioctl.h])
  AX_VOLUTA_CHECK_HEADERS([sys/mman.h])
  AX_VOLUTA_CHECK_HEADERS([sys/mount.h])
  AX_VOLUTA_CHECK_HEADERS([sys/uio.h])
  AX_VOLUTA_CHECK_HEADERS([sys/select.h])
  AX_VOLUTA_CHECK_HEADERS([sys/un.h])
  AX_VOLUTA_CHECK_HEADERS([netinet/in.h])
  AX_VOLUTA_CHECK_HEADERS([netinet/udp.h])
  AX_VOLUTA_CHECK_HEADERS([netinet/tcp.h])
  AX_VOLUTA_CHECK_HEADERS([arpa/inet.h])
  AX_VOLUTA_CHECK_HEADERS([linux/kernel.h])
  AX_VOLUTA_CHECK_HEADERS([linux/types.h])
  AX_VOLUTA_CHECK_HEADERS([linux/stat.h])
  AX_VOLUTA_CHECK_HEADERS([linux/falloc.h])
  AX_VOLUTA_CHECK_HEADERS([linux/fs.h])
  AX_VOLUTA_CHECK_HEADERS([linux/fuse.h])
  AX_VOLUTA_CHECK_HEADERS([linux/fiemap.h])
  AX_VOLUTA_CHECK_HEADERS([linux/limits.h])
])

AC_DEFUN([AX_VOLUTA_NEED_LIBS],
[
  AX_PTHREAD
  AX_LIB_GCRYPT([yes])

  AM_PATH_LIBGCRYPT(1.8.1, :,
    AC_MSG_ERROR([Unable to find libgcrypt]))

  AC_SEARCH_LIBS([uuid_generate], [uuid], :,
    AC_MSG_ERROR([Unable to find libuuid]))

  AC_SEARCH_LIBS([unw_backtrace], [unwind], :,
    AC_MSG_ERROR([Unable to find libunwind]))

  AC_SEARCH_LIBS([cap_clear], [cap], :,
    AC_MSG_ERROR([Unable to find libcap]))
])

