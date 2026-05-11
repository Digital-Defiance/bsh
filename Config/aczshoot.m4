AC_DEFUN([bsh_OOT],
[
AC_CHECK_HEADERS(stdarg.h varargs.h termios.h termio.h)

AC_TYPE_SIGNAL

AC_DEFINE([BSH_OOT_MODULE], [], [Out-of-tree module])
])
