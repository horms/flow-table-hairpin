#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(flow-table-hairpin, 0.1, simon.horman@netronome.com)
AC_CONFIG_SRCDIR([flow-table-hairpind/flow-table-hairpind.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC_C99
AC_PROG_CC
AC_PROG_INSTALL

AM_MISSING_PROG([AUTOM4TE], [autom4te])

LT_INIT()

# Checks for libraries.
PKG_CHECK_MODULES(LIBNL_GENL_3, libnl-genl-3.0 >= 3.1,
                  [have_libnl_genl_3=yes], [have_libnl_genl_3=no])
if (test "${have_libnl_genl_3}" = "yes"); then
	CFLAGS+=" $LIBNL_GENL_3_CFLAGS"
	LIBS+=" $LIBNL_GENL_3_LIBS"
fi

PKG_CHECK_MODULES(LIBFLOW_TABLE, libflow-table,
                  [have_libflow_table=yes], [have_libflow_table=no])
if (test "${have_libflow_table}" = "yes"); then
	CFLAGS+=" $LIBFLOW_TABLE_CFLAGS"
	LIBS+=" $LIBFLOW_TABLE_LIBS"
fi

PKG_CHECK_MODULES(JSON_C, json-c, [have_json_c=yes], [have_json_c=no])
if (test "${have_json_c}" = "yes"); then
	CFLAGS+=" $JSON_C_CFLAGS"
	LIBS+=" $JSON_C_LIBS"
fi

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
