[![build status](https://ci.gitlab.com/projects/684/status.png?ref=master)](https://gitlab.com/gnutls/gnutls/builds)

# GnuTLS -- Information for developers

This file contains instructions for developers and advanced users that
want to build from version controlled sources.

We require several tools to check out and build the software, including:

* [Make](http://www.gnu.org/software/make/)
* [Automake](http://www.gnu.org/software/automake/) (use 1.11.3 or later)
* [Autoconf](http://www.gnu.org/software/autoconf/)
* [Autogen](http://www.gnu.org/software/autogen/) (use 5.16 or later)
* [Libtool](http://www.gnu.org/software/libtool/)
* [Gettext](http://www.gnu.org/software/gettext/)
* [Texinfo](http://www.gnu.org/software/texinfo/)
* [Tar](http://www.gnu.org/software/tar/)
* [Gzip](http://www.gnu.org/software/gzip/)
* [Texlive & epsf](http://www.tug.org/texlive/) (for PDF manual)
* [GTK-DOC](http://www.gtk.org/gtk-doc/) (for API manual)
* [Git](http://git-scm.com/)
* [Perl](http://www.cpan.org/)
* [Nettle](http://www.lysator.liu.se/~nisse/nettle/)
* [Guile](http://www.gnu.org/software/guile/)
* [p11-kit](http://p11-glue.freedesktop.org/p11-kit.html)
* [gperf](http://www.gnu.org/software/gperf/)
* [libtasn1](http://josefsson.org/libtasn1/) (optional)
* [Libidn](http://www.gnu.org/software/libidn/) (optional, for internationalization of DNS)
* [AWK](http://www.gnu.org/software/awk/) (for make dist, pmccabe2html)
* [git2cl](http://savannah.nongnu.org/projects/git2cl/) (for make dist, ChangeLog)
* [bison](http://www.gnu.org/software/bison) (for datetime parser in certtool)
* [libunbound](https://unbound.net/) (for DANE support)
* [abi-compliance-checker](http://ispras.linuxbase.org/index.php/ABI_compliance_checker) (for make dist)

The required software is typically distributed with your operating
system, and the instructions for installing them differ.  Here are
some hints:

Debian/Ubuntu:
```
apt-get install -y git-core autoconf libtool gettext autopoint
apt-get install -y automake autogen nettle-dev libp11-kit-dev libtspi-dev
apt-get install -y guile-2.0-dev libtasn1-6-dev libidn11-dev gawk gperf git2cl
apt-get install -y libunbound-dev dns-root-data bison help2man gtk-doc-tools
apt-get install -y texinfo texlive texlive-generic-recommended texlive-extra-utils
```

Fedora/RHEL:
```
yum install -y git autoconf libtool gettext-devel automake autogen
yum install -y automake autogen nettle-devel p11-kit-devel autogen-libopts-devel
yum install -y trousers-devel guile-devel libtasn1-devel libidn-devel gawk gperf git2cl
yum install -y unbound-devel bison help2man gtk-doc texinfo texlive
```

Sometimes, you may need to install more recent versions of Automake,
Nettle, P11-kit and Autogen, which you will need to build from sources. 

Dependencies that are used during make check are listed below. Moreover,
for basic interoperability testing you may want to install openssl
and polarssl.

* [Valgrind](http://valgrind.org/) (optional)
* [Libasan](https://gcc.gnu.org//) (optional)
* [datefudge](http://packages.debian.org/datefudge) (optional)
* [nodejs](http://nodejs.org/) (needed for certain test cases)
* [softhsm](http://www.opendnssec.org/softhsm/) (for testing smart card support)
* [dieharder](http://www.phy.duke.edu/~rgb/General/dieharder.php) (for testing PRNG)

Debian/Ubuntu:
```
apt-get install -y valgrind libasan1 nodejs softhsm datefudge
apt-get install -y dieharder libpolarssl-runtime openssl
```

Fedora/RHEL:
```
yum install -y valgrind libasan nodejs softhsm datefudge
yum install -y dieharder mbedtls-utils openssl
```


To download the version controlled sources:

```
$ git clone git@gitlab.com:gnutls/gnutls.git
$ cd gnutls
$ git submodule update --init
```

The next step is to run autoreconf (etc) and then ./configure:

```
$ make bootstrap
```

When built this way, some developer defaults will be enabled.  See
cfg.mk for details.

Then build the project normally, and run the test suite.

```
$ make
$ make check
```

Individual tests that may require additional hardware (e.g., smart cards)
are:
```
$ sh tests/suite/testpkcs11
```

# Building for windows

It is recommended to cross compile using Fedora and the following
dependencies:

```
yum install -y wine mingw32-nettle mingw32-libtasn1 mingw32-gcc
```

and build as:

```
mingw32-configure --enable-local-libopts --disable-non-suiteb-curves --disable-doc --without-p11-kit
mingw32-make
mingw32-make check
```

# Contributing

If you wish to contribute, you may read more about our [coding style](doc/README.CODING_STYLE).
Note that when contributing code that is not assigned to FSF, you will
need to assert that the contribution is in accordance to the "Developer's
Certificate of Origin" as found in the file [DCO.txt](doc/DCO.txt).
That can be done by sending a mail with your real name to the gnutls-devel
mailing list. Then just make sure that your contributions (patches),
contain a "Signed-off-by" line, with your name and e-mail address. 
To automate the process use "git am -s" to produce patches.

Happy hacking!

----------------------------------------------------------------------
Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.
