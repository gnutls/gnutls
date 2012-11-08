eval '(exit $?0)' && eval 'exec perl -wST "$0" ${1+"$@"}'
  & eval 'exec perl -wST "$0" $argv:q'
    if 0;

# Copyright (C) 2011-2012 Free Software Foundation, Inc.
#
# This file is part of GnuTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

# given a header file in stdin it will print all functions

my $line;
my $func;

while ($line=<STDIN>) {

  if ($line !~ m/typedef/ && $line !~ m/Copyright/ && $line !~ m/doc-skip/) {
    $func = '';
    
    if ($line =~ m/^\s*\w+[\s\*]+([A-Za-z0-9_]+)\s*\([^\)]+/) {
        $func = $1;
    }

    if ($line =~ m/^\s*\w+\s+\w+[\s\*]+([A-Za-z0-9_]+)\s*\([^\)]+/) {
        $func = $1;
    }

    if ($line =~ m/^[\s\*]*([A-Za-z0-9_]+)\s*\([^\)]+/) {
        $func = $1;
    }
    
    if ($func ne '' && ($func =~ m/gnutls_.*/ || $func =~ m/dane_.*/)) {
      print $func . "\n";
    }
  }

}
