#!/usr/bin/perl

# Copyright (C) 2002-2012 Free Software Foundation, Inc.
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
# along with this file.  If not, see <https://www.gnu.org/licenses/>.

sub key_of_record {
  local($record) = @_;

  # Split record into lines:
  my @lines = split /\n/, $record;

  my ($i) = 1;
  my ($key) = $lines[$i]; 

  while( !($key =~ m/^\\functionTitle\{(.*)\}/) && ($i < 5)) { $i=$i+1; $key = $lines[$i]; }

  return $key;
}

$/="\n\\end{function}";          # Records are separated by blank lines.
@records = <>;  # Read in whole file, one record per array element.

@records = sort { key_of_record($a) cmp key_of_record($b) } @records;
print @records;
