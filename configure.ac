AC_INIT([cryptopass], [1.1.0], [vasek.gello@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR
AC_CHECK_HEADER([assert.h],
                [AC_DEFINE([HAVE_ASSERT_H], [1],
                [Define to 1 if you have <assert.h>.])],
                [AC_MSG_ERROR([Sorry, can't do anything for you])])
AC_CHECK_HEADER([stdio.h],
                [AC_DEFINE([HAVE_STDIO_H], [1],
                [Define to 1 if you have <stdio.h>.])],
                [AC_MSG_ERROR([Sorry, can't do anything for you])])
AC_CHECK_HEADER([termios.h],
                [AC_DEFINE([HAVE_TERMIOS_H], [1],
                [Define to 1 if you have <termios.h>.])],
                [AC_MSG_WARN([Missing termios.h: master password will be visible!])])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 lib/Makefile
 src/Makefile
 tests/Makefile
])
AC_OUTPUT
