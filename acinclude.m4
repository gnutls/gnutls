dnl *************** Autoconf macros for libgcrypt (1.1.3) ***************
dnl $id$

# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBGCRYPT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgcrypt, and define GCRYPT_CFLAGS and GCRYPT_LIBS
dnl
AC_DEFUN(AM_PATH_LIBGCRYPT,
[dnl
dnl Get the cflags and libraries from the libgcrypt-config script
dnl
AC_ARG_WITH(libgcrypt-prefix,
          [  --with-libgcrypt-prefix=PFX   Prefix where libgcrypt is installed (optional)],
          libgcrypt_config_prefix="$withval", libgcrypt_config_prefix="")
AC_ARG_ENABLE(libgcrypttest,
          [  --disable-libgcrypttest    Do not try to compile and run a test libgcrypt program],
          , enable_libgcrypttest=yes)

  if test x$libgcrypt_config_prefix != x ; then
     libgcrypt_config_args="$libgcrypt_config_args --prefix=$libgcrypt_config_prefix"
     if test x${LIBGCRYPT_CONFIG+set} != xset ; then
        LIBGCRYPT_CONFIG=$libgcrypt_config_prefix/bin/libgcrypt-config
     fi
  fi

  AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config, no)
  min_libgcrypt_version=ifelse([$1], ,1.1.0,$1)
  AC_MSG_CHECKING(for libgcrypt - version >= $min_libgcrypt_version)
  no_libgcrypt=""
  if test "$LIBGCRYPT_CONFIG" = "no" ; then
    no_libgcrypt=yes
  else
    LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --cflags`
    LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --libs`
    libgcrypt_config_version=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --version`
    if test "x$enable_libgcrypttest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
      LIBS="$LIBS $LIBGCRYPT_LIBS"
dnl
dnl Now check if the installed libgcrypt is sufficiently new. Also sanity
dnl checks the results of libgcrypt-config to some extent
dnl
      rm -f conf.libgcrypttest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

int
main ()
{
    system ("touch conf.libgcrypttest");

    if( strcmp( gcry_check_version(NULL), "$libgcrypt_config_version" ) )
    {
      printf("\n*** 'libgcrypt-config --version' returned %s, but LIBGCRYPT (%s)\n",
             "$libgcrypt_config_version", gcry_check_version(NULL) );
      printf("*** was found! If libgcrypt-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBGCRYPT. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libgcrypt-config was wrong, set the environment variable LIBGCRYPT_CONFIG\n");
      printf("*** to point to the correct copy of libgcrypt-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(gcry_check_version(NULL), GCRYPT_VERSION ) )
    {
      printf("\n*** LIBGCRYPT header file (version %s) does not match\n", GCRYPT_VERSION);
      printf("*** library (version %s)\n", gcry_check_version(NULL) );
    }
    else
    {
      if ( gcry_check_version( "$min_libgcrypt_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBGCRYPT (%s) was found.\n",
                gcry_check_version(NULL) );
        printf("*** You need a version of LIBGCRYPT newer than %s. The latest version of\n",
               "$min_libgcrypt_version" );
        printf("*** LIBGCRYPT is always available from ftp://ftp.gnupg.org/pub/libgcrypt/gnupg.\n");
        printf("*** (It is distributed along with GnuPG).\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libgcrypt-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBGCRYPT, but you can also set the LIBGCRYPT_CONFIG environment to point to the\n");
        printf("*** correct copy of libgcrypt-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_libgcrypt=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_libgcrypt" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libgcrypttest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBGCRYPT_CONFIG" = "no" ; then
       echo "*** The libgcrypt-config script installed by LIBGCRYPT could not be found"
       echo "*** If LIBGCRYPT was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBGCRYPT_CONFIG environment variable to the"
       echo "*** full path to libgcrypt-config."
     else
       if test -f conf.libgcrypttest ; then
        :
       else
          echo "*** Could not run libgcrypt test program, checking why..."
          CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
          LIBS="$LIBS $LIBGCRYPT_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
],      [ return !!gcry_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBGCRYPT or finding the wrong"
          echo "*** version of LIBGCRYPT. If it is not finding LIBGCRYPT, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBGCRYPT was incorrectly installed"
          echo "*** or that you have moved LIBGCRYPT since it was installed. In the latter case, you"
          echo "*** may want to edit the libgcrypt-config script: $LIBGCRYPT_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBGCRYPT_CFLAGS=""
     LIBGCRYPT_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBGCRYPT_CFLAGS)
  AC_SUBST(LIBGCRYPT_LIBS)
  rm -f conf.libgcrypttest
])

dnl Autoconf macros for libmcrypt
dnl $id$

# This script detects libmcrypt version and defines
# LIBMCRYPT_CFLAGS, LIBMCRYPT_LIBS
# and LIBMCRYPT24 or LIBMCRYPT22 depending on libmcrypt version
# found.

# Modified for LIBMCRYPT -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBMCRYPT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libmcrypt, and define LIBMCRYPT_CFLAGS and LIBMCRYPT_LIBS
dnl
AC_DEFUN(AM_PATH_LIBMCRYPT,
[dnl
dnl Get the cflags and libraries from the libmcrypt-config script
dnl
AC_ARG_WITH(libmcrypt-prefix,
          [  --with-libmcrypt-prefix=PFX   Prefix where libmcrypt is installed (optional)],
          libmcrypt_config_prefix="$withval", libmcrypt_config_prefix="")

  if test x$libmcrypt_config_prefix != x ; then
     libmcrypt_config_args="$libmcrypt_config_args --prefix=$libmcrypt_config_prefix"
     if test x${LIBMCRYPT_CONFIG+set} != xset ; then
        LIBMCRYPT_CONFIG=$libmcrypt_config_prefix/bin/libmcrypt-config
     fi
  fi

  AC_PATH_PROG(LIBMCRYPT_CONFIG, libmcrypt-config, no)
  min_libmcrypt_version=ifelse([$1], ,2.4.0,$1)
  AC_MSG_CHECKING(for libmcrypt - version >= $min_libmcrypt_version)
  no_libmcrypt=""
  if test "$LIBMCRYPT_CONFIG" = "no" ; then
dnl libmcrypt-config was not found (pre 2.4.11 versions)
dnl Try to detect libmcrypt version
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

int
main ()
{
#if MCRYPT_API_VERSION <= 19991015 
/* version 2.2 */
    return 0;
#else
/* version 2.4 */
    return 1;
#endif /* 19991015 */
}
],  libmcrypt_config_version="2.2.0"
    if test x$libmcrypt_config_prefix != x ; then
	TTLIBS="-L${libmcrypt_config_prefix}/libs"
	TTINCLUDE="-I${libmcrypt_config_prefix}/include"
    fi
    LIBMCRYPT_CFLAGS="${TTINCLUDE}"
    LIBMCRYPT_LIBS="${TTLIBS} -lmcrypt"
    AC_DEFINE(LIBMCRYPT22)

,   libmcrypt_config_version="2.4.0"
    if test x$libmcrypt_config_prefix != x ; then
	TTLIBS="-L${libmcrypt_config_prefix}/libs"
	TTINCLUDE="-I${libmcrypt_config_prefix}/include"
    fi
    LIBMCRYPT_CFLAGS="${TTINCLUDE}"
    LIBMCRYPT_LIBS="${TTLIBS} -lmcrypt -lltdl ${LIBADD_DL}"
    AC_DEFINE(LIBMCRYPT24))
  else
dnl libmcrypt-config was found
    LIBMCRYPT_CFLAGS=`$LIBMCRYPT_CONFIG $libmcrypt_config_args --cflags`
    LIBMCRYPT_LIBS=`$LIBMCRYPT_CONFIG $libmcrypt_config_args --libs`
    libmcrypt_config_version=`$LIBMCRYPT_CONFIG $libmcrypt_config_args --version`
    AC_DEFINE(LIBMCRYPT24)
  fi

  ac_save_CFLAGS="$CFLAGS"
  ac_save_LIBS="$LIBS"
  CFLAGS="$CFLAGS $LIBMCRYPT_CFLAGS"
  LIBS="$LIBS $LIBMCRYPT_LIBS"

dnl
dnl Now check if the installed libmcrypt is sufficiently new. Also sanity
dnl checks the results of libmcrypt-config to some extent
dnl
      rm -f conf.libmcrypttest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

#define TWO "2.2"

int
main ()
{
#if MCRYPT_API_VERSION <= 20010201

#if MCRYPT_API_VERSION <= 19991015 
/* version 2.2 */
    int x = mcrypt_get_key_size(MCRYPT_TWOFISH_128);
    system ("touch conf.libmcrypttest");

    if( strncmp( TWO, "$min_libmcrypt_version", strlen(TWO))) {
      printf("\n*** Requested libmcrypt %s, but LIBMCRYPT (%s)\n",
             "$min_libmcrypt_version", TWO );
      printf("*** was found!\n"); 
      return 1;
    }
    return 0;
#else
/* version 2.4 before 11 */
    MCRYPT td = mcrypt_module_open("twofish", NULL, "cbc", NULL);
    system ("touch conf.libmcrypttest");
    mcrypt_module_close(td);

    return 0;
#endif /* 19991015 */

#else

    system ("touch conf.libmcrypttest");

    if( strcmp( mcrypt_check_version(NULL), "$libmcrypt_config_version" ) )
    {
      printf("\n*** 'libmcrypt-config --version' returned %s, but LIBMCRYPT (%s)\n",
             "$libmcrypt_config_version", mcrypt_check_version(NULL) );
      printf("*** was found! If libmcrypt-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBMCRYPT. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libmcrypt-config was wrong, set the environment variable LIBMCRYPT_CONFIG\n");
      printf("*** to point to the correct copy of libmcrypt-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(mcrypt_check_version(NULL), LIBMCRYPT_VERSION ) )
    {
      printf("\n*** LIBMCRYPT header file (version %s) does not match\n", LIBMCRYPT_VERSION);
      printf("*** library (version %s)\n", mcrypt_check_version(NULL) );
    }
    else
    {
      if ( mcrypt_check_version( "$min_libmcrypt_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBMCRYPT (%s) was found.\n",
                mcrypt_check_version(NULL) );
        printf("*** You need a version of LIBMCRYPT newer than %s. The latest version of\n",
               "$min_libmcrypt_version" );
        printf("*** LIBMCRYPT is always available from ftp://mcrypt.hellug.gr/pub/mcrypt.\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libmcrypt-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBMCRYPT, but you can also set the LIBMCRYPT_CONFIG environment to point to the\n");
        printf("*** correct copy of libmcrypt-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;

#endif /* 20010201 */

}
],, no_libmcrypt=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"


  if test "x$no_libmcrypt" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libmcrypttest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     
     if test -f conf.libmcrypttest ; then
        :
     else
          echo "*** Could not run libmcrypt test program, checking why..."
          CFLAGS="$CFLAGS $LIBMCRYPT_CFLAGS"
          LIBS="$LIBS $LIBMCRYPT_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
],      [ 
#if MCRYPT_API_VERSION <= 20010201

#if MCRYPT_API_VERSION <= 19991015 
/* version 2.2 */
    int x = mcrypt_get_key_size(MCRYPT_TWOFISH_128);
    return 0;
#else
/* version 2.4 before 11 */
    MCRYPT td = mcrypt_module_open("twofish", NULL, "cbc", NULL);
    mcrypt_module_close(td);
    return 0;
#endif /* 19991015 */
#else

return !!mcrypt_check_version(NULL); 

#endif /* 20010201 */

],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBMCRYPT or finding the wrong"
          echo "*** version of LIBMCRYPT. If it is not finding LIBMCRYPT, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBMCRYPT was incorrectly installed"
          echo "*** or that you have moved LIBMCRYPT since it was installed. In the latter case, you"
          echo "*** may want to edit the libmcrypt-config script: $LIBMCRYPT_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
     fi
     
     LIBMCRYPT_CFLAGS=""
     LIBMCRYPT_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.libmcrypttest
  AC_SUBST(LIBMCRYPT_CFLAGS)
  AC_SUBST(LIBMCRYPT_LIBS)
])


dnl OPENCDK stuff
dnl Autoconf macros for opencdk
dnl $id$

# Configure paths for LIBOPENCDK
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09
# Modified for OpenCDK
# Timo Schulz   02-02-22

dnl AM_PATH_LIBOPENCDK([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libopencdk, and define CDK_CFLAGS and CDK_LIBS
dnl
AC_DEFUN(AM_PATH_LIBOPENCDK,
[dnl
dnl Get the cflags and libraries from the opencdk-config script
dnl
AC_ARG_WITH(libopen-prefix,
          [  --with-libopencdk-prefix=PFX   Prefix where libopencdk is installed (optional)],
          libopencdk_config_prefix="$withval", libopencdk_config_prefix="")
AC_ARG_ENABLE(libopencdktest,
          [  --disable-libopencdktest    Do not try to compile and run a test libopencdk program],
          , enable_libopencdktest=yes)

  if test x$libopencdk_config_prefix != x ; then
     libopencdk_config_args="$libopencdk_config_args --prefix=$libopencdk_config_prefix"
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
        printf("*** LIBOPENCDK is always available from ftp://ftp.gnupg.org/pub/libopencdk/gnupg.\n");
        printf("*** (It is distributed along with GnuPG).\n");
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
