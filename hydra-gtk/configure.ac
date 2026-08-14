dnl Process this file with autoconf to produce a configure script.

AC_INIT([xhydra],[0.1])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_PROG_CC

pkg_modules="gtk+-3.0 >= 3.24.24"
PKG_CHECK_MODULES(PACKAGE, [$pkg_modules])
AC_SUBST(PACKAGE_CFLAGS)
AC_SUBST(PACKAGE_LIBS)

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT
# Check for libxml2 (required for Nmap XML parsing)
PKG_CHECK_MODULES([XML2], [libxml-2.0], [have_xml2=yes], [have_xml2=no])

if test "x$have_xml2" = "xyes"; then
    AC_DEFINE([HAVE_XML2], [1], [Define to 1 if you have libxml2])
    echo "Nmap integration: enabled"
else
    echo "Nmap integration: disabled (libxml2 not found)"
fi

AM_CONDITIONAL([HAVE_XML2], [test "x$have_xml2" = "xyes"])
