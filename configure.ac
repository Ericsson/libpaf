 -*- Autoconf -*-

AC_INIT(libpaf, 0.1, [mattias.ronnblom@ericsson.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
AC_PREREQ([2.63])
AC_PROG_CC

AC_USE_SYSTEM_EXTENSIONS

LT_INIT

AC_CHECK_PROG(HAVE_VALGRIND, valgrind, yes, no)

AM_CONDITIONAL(VALGRIND, [test x$HAVE_VALGRIND = xyes])

AC_CHECK_PROG(HAVE_PDFLATEX, pdflatex, yes, no)

AM_CONDITIONAL(PDFLATEX, [test x$HAVE_PDFLATEX = xyes])

AC_CHECK_HEADERS(xcm.h, [],
                 [AC_MSG_ERROR([Unable to find XCM header files.])])
AC_CHECK_LIB(xcm, xcm_connect, [],
             [AC_MSG_ERROR([Unable to find the XCM library.])])
AC_CHECK_HEADERS(jansson.h, [],
                 [AC_MSG_ERROR([Unable to find Jansson header files.])])
AC_CHECK_LIB(jansson, json_loads, [],
             [AC_MSG_ERROR([Unable to find the Jansson library.])])

AC_ARG_ENABLE([lttng],
    AS_HELP_STRING([--disable-lttng], [disable LTTng logging support]))

AM_CONDITIONAL([LTTNG], [test "x$enable_lttng" != "xno"])

AS_IF([test "x$enable_lttng" != "xno"], [
	AC_CHECK_LIB(lttng-ust, ltt_probe_register, [],
	             [AC_MSG_ERROR([Unable to find the lttng-ust library. Disable LTTng to avoid this dependency.])])
])

AM_PATH_PYTHON(3.5)

AC_SUBST([AM_CFLAGS])

AC_CONFIG_FILES([Makefile doc/doxygen.conf])
AC_CONFIG_FILES([app/pafappc], [chmod a+x app/pafappc])

AC_OUTPUT
