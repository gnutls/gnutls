dnl Autoconf macros for opencdk
dnl $id$

# Configure paths for LIBOPENCDK
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09
# Modified for OpenCDK
# Timo Schulz   02-04-06

dnl AM_PATH_LIBOPENCDK([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libopencdk, and define CDK_CFLAGS and CDK_LIBS
dnl
AC_DEFUN([AM_PATH_LIBOPENCDK],
[dnl
dnl Get the cflags and libraries from the opencdk-config script
dnl
AC_ARG_WITH(libopencdk-prefix,
          [  --with-libopencdk-prefix=PFX   Prefix where libopencdk is installed (optional)],
          libopencdk_config_prefix="$withval", libopencdk_config_prefix="")
AC_ARG_ENABLE(libopencdktest,
          [  --disable-libopencdktest    Do not try to compile and run a test libopencdk program],
          , enable_libopencdktest=yes)

  if test x$libopencdk_config_prefix != x ; then
     if test x${LIBOPENCDK_CONFIG+set} != xset ; then
        LIBOPENCDK_CONFIG=$libopencdk_config_prefix/bin/opencdk-config
     fi
  fi

  AC_PATH_PROG(LIBOPENCDK_CONFIG, opencdk-config, no)
  min_libopencdk_version=ifelse([$1], ,1.1.0,$1)
  AC_MSG_CHECKING(for libopencdk - version >= $min_libopencdk_version)
  no_libopencdk=""
  if test "$LIBOPENCDK_CONFIG" = "no" ; then
    no_libopencdk=yes
  else
    LIBOPENCDK_CFLAGS=`$LIBOPENCDK_CONFIG $libopencdk_config_args --cflags`
    LIBOPENCDK_LIBS=`$LIBOPENCDK_CONFIG $libopencdk_config_args --libs`
    libopencdk_config_version=`$LIBOPENCDK_CONFIG $libopencdk_config_args --version`
    if test "x$enable_libopencdktest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBOPENCDK_CFLAGS"
      LIBS="$LIBS $LIBOPENCDK_LIBS"
dnl
dnl Now check if the installed libopencdk is sufficiently new. Also sanity
dnl checks the results of opencdk-config to some extent
dnl
      rm -f conf.libopencdktest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <opencdk.h>

int
main ()
{
    system ("touch conf.libopencdktest");

    if( strcmp( cdk_check_version(NULL), "$libopencdk_config_version" ) )
    {
      printf("\n*** 'opencdk-config --version' returned %s, but LIBOPENCDK (%s)\n",
             "$libopencdk_config_version", cdk_check_version(NULL) );
      printf("*** was found! If opencdk-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBOPENCDK. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If opencdk-config was wrong, set the environment variable LIBOPENCDK_CONFIG\n");
      printf("*** to point to the correct copy of opencdk-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(cdk_check_version(NULL), OPENCDK_VERSION ) )
    {
      printf("\n*** LIBOPENCDK header file (version %s) does not match\n", OPENCDK_VERSION);
      printf("*** library (version %s)\n", cdk_check_version(NULL) );
    }
    else
    {
      if ( cdk_check_version( "$min_libopencdk_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBOPENCDK (%s) was found.\n",
                cdk_check_version(NULL) );
        printf("*** You need a version of LIBOPENCDK newer than %s. The latest version of\n",
               "$min_libopencdk_version" );
        printf("*** LIBOPENCDK is always available from ftp://ftp.gnutls.org/pub/gnutls/opencdk/.\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the opencdk-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBOPENCDK, but you can also set the LIBOPENCDK_CONFIG environment to point to the\n");
        printf("*** correct copy of opencdk-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_libopencdk=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_libopencdk" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libopencdktest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBOPENCDK_CONFIG" = "no" ; then
       echo "*** The opencdk-config script installed by LIBOPENCDK could not be found"
       echo "*** If LIBOPENCDK was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBOPENCDK_CONFIG environment variable to the"
       echo "*** full path to opencdk-config."
     else
       if test -f conf.libopencdktest ; then
        :
       else
          echo "*** Could not run libopencdk test program, checking why..."
          CFLAGS="$CFLAGS $LIBOPENCDK_CFLAGS"
          LIBS="$LIBS $LIBOPENCDK_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <opencdk.h>
],      [ return !!cdk_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBOPENCDK or finding the wrong"
          echo "*** version of LIBOPENCDK. If it is not finding LIBOPENCDK, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBOPENCDK was incorrectly installed"
          echo "*** or that you have moved LIBOPENCDK since it was installed. In the latter case, you"
          echo "*** may want to edit the opencdk-config script: $LIBOPENCDK_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBOPENCDK_CFLAGS=""
     LIBOPENCDK_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBOPENCDK_CFLAGS)
  AC_SUBST(LIBOPENCDK_LIBS)
  rm -f conf.libopencdktest
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
