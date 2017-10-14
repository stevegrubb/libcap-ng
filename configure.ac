dnl
define([AC_INIT_NOTICE],
[### Generated automatically using autoconf version] AC_ACVERSION [
### Copyright 2009-2015 Steve Grubb <sgrubb@redhat.com>
###
### Permission is hereby granted, free of charge, to any person obtaining a
### copy of this software and associated documentation files (the "Software"),
### to deal in the Software without restriction, including without limitation
### the rights to use, copy, modify, merge, publish, distribute, sublicense,
### and/or sell copies of the Software, and to permit persons to whom the
### Software is furnished to do so, subject to the following conditions:
###
### The above copyright notice and this permission notice shall be included
### in all copies or substantial portions of the Software.
###
### THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
### IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
### FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
### THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
### OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
### ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
### OTHER DEALINGS IN THE SOFTWARE.
###
### For usage, run `./configure --help'
### For more detailed information on installation, read the file `INSTALL'.
###
### If configuration succeeds, status is in the file `config.status'.
### A log of configuration tests is in `config.log'.
])

AC_REVISION($Revision: 1.3 $)dnl
AC_INIT(libcap-ng,0.7.7)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])

echo Configuring libcap-ng $VERSION

AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

echo .
echo Checking for programs

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK

echo .
echo Checking for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(linux/capability.h, [], [AC_MSG_ERROR(linux/capability.h is required in order to build libcap-ng.)])
AC_CHECK_HEADERS(sys/xattr.h, [], [
	AC_CHECK_HEADERS(attr/xattr.h, [], [AC_MSG_WARN(attr/xattr.h not found, disabling file system capabilities.)])
	])
AC_CHECK_HEADERS(linux/securebits.h, [], [])

AC_C_CONST
AC_C_INLINE
AM_PROG_CC_C_O

ALLWARNS=""
ALLDEBUG="-g"
OPT="-O"
if test x"$GCC" = x"yes"; then
  OPT="-O2 -pipe"
  case "$target" in
    *linux*)
             ALLWARNS="-W -Wall -Wundef -Wpointer-arith -Wcast-align \
-Wwrite-strings -Waggregate-return -Wstrict-prototypes \
-Wmissing-prototypes -Wmissing-declarations -Wredundant-decls \
-Wnested-externs -Winline -Wfloat-equal -Wchar-subscripts"
             ;;
    esac
fi

ALLDEBUG="-g"
AC_ARG_WITH(debug,
[  --with-debug            turn on debugging [[default=no]]],
[
if test "x${withval}" = xyes; then
        DEBUG="$ALLDEBUG"
        OPT="-O"
        AM_CONDITIONAL(DEBUG, true)
else
        DEBUG="-DNDEBUG"
        AM_CONDITIONAL(DEBUG, false)
fi
],
[ DEBUG="-DNDEBUG"; AM_CONDITIONAL(DEBUG, false) ])

AC_ARG_WITH(warn,
[  --with-warn             turn on warnings [[default=yes]]],
[
if test "x${withval}" = xyes; then
        WARNS="$ALLWARNS"
else
        WARNS=""
fi
],WARNS="$ALLWARNS")
AC_SUBST(DEBUG)

AC_CHECK_HEADER(sys/syscall.h,
	[AC_DEFINE([HAVE_SYSCALL_H], [1],
	[Define to 1 if you have <sys/syscall.h>.])], [],)

AC_CHECK_PROG(swig_found, swig, yes, no)
if test x"${swig_found}" = x"no" ; then
	AC_MSG_WARN("Swig not found - python bindings will not be made")
fi
AM_CONDITIONAL(HAVE_SWIG, test x"${swig_found}" = x"yes")

AC_MSG_CHECKING(whether to create python bindings)
AC_ARG_WITH(python,
AS_HELP_STRING([--with-python],[enable building python bindings]),
use_python=$withval,
use_python=auto)
if test x$use_python = xno ; then
	python_found="no"
	AC_MSG_RESULT(no)
else
AC_MSG_RESULT(testing)
AM_PATH_PYTHON
PYINCLUDEDIR=`python${am_cv_python_version} -c "from distutils import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))"`
if test -f ${PYINCLUDEDIR}/Python.h ; then
	python_found="yes"
	AC_SUBST(PYINCLUDEDIR)
	AC_MSG_NOTICE(Python bindings will be built)
else
	python_found="no"
	if test x$use_python = xyes ; then
		AC_MSG_ERROR([Python explicitly required and python headers found])
	else
		AC_MSG_WARN("Python headers not found - python bindings will not be made")
	fi
fi
fi
AM_CONDITIONAL(HAVE_PYTHON, test ${python_found} = "yes")

AC_MSG_CHECKING(whether to create python3 bindings)
AC_ARG_WITH(python3,
AS_HELP_STRING([--with-python3],[enable building python3 bindings]),
use_python3=$withval,
use_python3=auto)
if test x$use_python3 = xno ; then
	AC_MSG_RESULT(no)
else
	if test ${python_found} = no ; then
		AC_MSG_RESULT(no)
		use_python3=no
	else
	AC_MSG_RESULT(yes)
	use_python3=yes
	AC_PATH_PROG([PYTHON3], [python3], [no])
	if test "$PYTHON3" == "no" ; then
		echo "The python3 program was not found in the search path. Please ensure"
		echo "that it is installed and its directory is included in the search path or"
		echo "pass --without-python3 to ./configure."
		exit 1
	fi
	PYTHON3_CFLAGS=`python3-config --cflags 2> /dev/null`
	PYTHON3_LIBS=`python3-config --libs 2> /dev/null`
	PYTHON3_INCLUDES=`python3-config --includes 2> /dev/null`
	AC_SUBST([PYTHON3_PREFIX], ['${prefix}'])
	AC_SUBST([PYTHON3_EXEC_PREFIX], ['${exec_prefix}'])
	PYTHON3_DIR=`$PYTHON3 -c "import distutils.sysconfig; \
	print(distutils.sysconfig.get_python_lib(0,0,prefix='$PYTHON3_PREFIX'))"`
	PYTHON3_EXECDIR=`$PYTHON3 -c "import distutils.sysconfig; \
	print(distutils.sysconfig.get_python_lib(1,0,prefix='$PYTHON3_EXEC_PREFIX'))"`
	AC_SUBST(PYTHON3_CFLAGS)
	AC_SUBST(PYTHON3_LIBS)
	AC_SUBST(PYTHON3_INCLUDES)
	AC_SUBST(python3dir, $PYTHON3_DIR)
	AC_SUBST(py3execdir, $PYTHON3_EXECDIR)
	fi
fi
AM_CONDITIONAL(USE_PYTHON3, test ${use_python3} = "yes")

AC_OUTPUT(Makefile src/Makefile src/libcap-ng.pc src/test/Makefile 
	bindings/Makefile bindings/python/Makefile 
	bindings/python3/Makefile bindings/src/Makefile 
	bindings/python/test/Makefile utils/Makefile 
	m4/Makefile docs/Makefile)

echo .
echo "

  libcap-ng Version:      $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
"
