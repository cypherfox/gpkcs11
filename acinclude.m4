dnl (c) 1999 TC TrustCenter for Security in Data Networks GmbH
dnl
dnl set some standard value for TC

dnl TC_INIT(PACKAGE_NAME)
AC_DEFUN(TC_INIT, [\

TC_HOME=/usr/pcshare/tc

dnl weitere Konfigurationen lesen
dnl diese konfiguration kann jederzeit global angepasst werden. 
if test -r ${TC_HOME}/etc/tcpu.config
 then
  . ${TC_HOME}/etc/tcpu.config
 fi

if test $prefix != NONE 
then 
 INCLUDES="-I${prefix}/include $INCLUDES"
 LDFLAGS="-L${prefix}/lib $LDFLAGS"
fi

AC_SUBST(TC_HOME)

dnl ########################################################
dnl set the default CFLAGS and CXXFLAGS and enable to switch
dnl ########################################################

AC_ARG_ENABLE(optimization, [\
  --enable-optimization   activate optimizationm, turn off debugging code
                          inclusion and -Wall (default is off.)], 
 [
    AC_MSG_CHECKING([optimization settings])
  if test $enable_optimization = "yes"; then 
    AC_MSG_RESULT([-Wall disabled, -O2 enabled])
    CFLAGS="-g -O2 " 
    CXXFLAGS="-g -O2 "
  else 
    AC_MSG_RESULT([-g and -Wall enabled]) 
    CFLAGS="-g -Wall "
    CXXFLAGS="-g -Wall "
  fi 
 ] , [ \
 AC_MSG_CHECKING([optimization settings])
 AC_MSG_RESULT([-g and -Wall enabled]) 
 CFLAGS="-g -Wall "
 CXXFLAGS="-g -Wall "
 ]
)
dnl ######################
dnl activate code coverage
dnl ######################

AC_ARG_ENABLE(code-coverage, [\
  --enable-code-coverage  activate instrumentalization for code coverage 
                          to be used with gcov (default is off.)], 
 [
    AC_MSG_CHECKING([code coverage analysis])
  if test $enable_code_coverage = "yes"; then 
    AC_MSG_RESULT([enabled])
    CFLAGS="$CFLAGS -ftest-coverage"
    CXXFLAGS="$CXXFLAGS -ftest-coverage"
  else 
    AC_MSG_RESULT([disabled]) 
  fi 
 ] , [ \
 AC_MSG_CHECKING([optimization settings])
 AC_MSG_RESULT([disabled]) 
 ]
)

dnl #######################################################
dnl  create debuging options and assertion inclusion control
dnl #######################################################
AC_ARG_ENABLE(debug, [\
  --enable-debug[=LEVEL]  Set the debug level to LEVEL (default is 1 if the 
                          option is called, 0 if not called). A LEVEL set to 0 
                          will disable TC_ASSERT.],
[
  if test "$enable_debug" = "yes" 
   then 
    TC_DEBUG_LEVEL=1
   elif test "$enable_debug" = "no"
    then
     TC_DEBUG_LEVEL=0
   else 
    TC_DEBUG_LEVEL="$enable_debug"
   fi
], [
 TC_DEBUG_LEVEL=0
])

AC_ARG_ENABLE(assert, [\
  --enable-assert         Activate the assertions independently from the 
                          debug level. Default is the setting determined 
                          by the debug level.],
[
AC_MSG_RESULT([Setting Assertions: $enable_assert])
 if test "$enable_assert" = "yes"
  then 
AC_MSG_RESULT([Setting Assertions: force assert])
   FORCE_ASSERT="1"
  else
   FORCE_ASSERT="0"
  fi
], [
   FORCE_ASSERT="0"
])

AC_MSG_CHECKING([debugging settings])
if test "$TC_DEBUG_LEVEL" != "0"
 then 
  AC_DEFINE_UNQUOTED(DEBUG, $TC_DEBUG_LEVEL, [activate and set level of debuggin])
  AC_MSG_RESULT([activate debugging])
 else
  AC_MSG_RESULT([no debugging])
 fi

dnl the wierd code with the double depth variable evaluation
dnl stems from the fact that I can neither use '-o' in the test
dnl nor double invocation of the AC_DEFINE for USE_ASSERT, since
dnl autoheader is rather stupid about those things.
AC_MSG_CHECKING([assertion settings])
if test "$TC_DEBUG_LEVEL" != "0"
 then
  DO_ASSERT=1
 elif test "$FORCE_ASSERT" = "1"
  then
   DO_ASSERT=1
  else
   DO_ASSERT=0
   AC_DEFINE(NDEBUG, 1, [turn of system assertions])
   AC_MSG_RESULT([no assertions])
fi

if test "$DO_ASSERT" = "1"
 then
  AC_DEFINE(USE_ASSERT, 1, [activate and set level of debugging])
  AC_MSG_RESULT([active assertions])
 fi

dnl #######################################################
dnl  create profiling options
dnl #######################################################
AC_ARG_ENABLE(profiling, [\
  --enable-profiling Enable the profiling option.],
[
  if test "$enable_profiling" = "yes" 
   then 
    CFLAGS="-pg $CFLAGS" 
    CXXFLAGS="-pg $CXXFLAGS"
    AC_MSG_RESULT([-pg (Profiling) enabled]) 
   fi
], [
    AC_MSG_RESULT([Profiling disabled]) 
])

dnl ########################################################
dnl check for the existence of a share/tcpu in prefix
dnl ########################################################
dnl the directory might contain the latest version of the 
dnl m4 files.
if test -d $prefix/share/tcpu
 then
  PREFIX_ACLOCAL="-I $prefix/share/tcpu"
 else
  PREFIX_ACLOCAL="-I $TC_HOME/share/tcpu"
 fi
 AC_SUBST(PREFIX_ACLOCAL)



dnl end of TC_INIT
])


dnl 
dnl Macro: TC_CHECK_DEFINE - Search for defined symbol in header
dnl Syntax: TC_CHEKC_DEFINE(symbol,header-file[,found-action[,not-found-action]])
dnl
AC_DEFUN(TC_CHECK_DEFINE, [\
 AC_MSG_CHECKING([for $1 in $2])
 AC_EGREP_CPP(__TC_CHECK_DEFUN_SET__,
 [#include <$2>
  #ifdef $1
  #error got here
  __TC_CHECK_DEFUN_SET__
  #endif
 ],[
  AC_MSG_RESULT([yes])
  $3
 ],[
  AC_MSG_RESULT([no])
  $4
 ])
])


dnl 
dnl Macro: TC_ARCH_INSTALL - install the architecture dependant files in 
dnl                          architecture specific directories.
dnl Syntax:TC_ARCH_INSTALL
AC_DEFUN(TC_ARCH_INSTALL, [\

 AC_REQUIRE([AC_CANONICAL_HOST])

 if test "x$target" = "xNONE"
  then
   target="$host"
  fi

 if test "x$exec_prefix" != "xNONE"
  then 
   exec_prefix="$exec_prefix/$target" 
  else 
   AC_MSG_RESULT([prefix is $prefix ])
   if test "x$prefix" != "xNONE"
    then
     exec_prefix="$prefix/$target" 
    else
     exec_prefix="$ac_default_prefix/$target"
    fi
  fi
])
