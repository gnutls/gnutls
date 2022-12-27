#!/usr/bin/perl -w
#
# Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
# Written by David Howells (dhowells@redhat.com)
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <https://www.gnu.org/licenses/>.

#
# Generate random but valid ASN.1 data.
#
# Format:
#
#	asn1random.pl >output
#
use strict;

my $depth = 0;
my $maxdepth = 12;

#print STDERR "SEED: ", srand(), "\n";

###############################################################################
#
# Generate a header
#
###############################################################################
sub emit_asn1_hdr($$)
{
    my ($tag, $len) = @_;
    my $output = "";
    my $l;

    if ($len < 0x80) {
	$l = $len;
    } elsif ($len <= 0xff) {
	$l = 0x81;
    } elsif ($len <= 0xffff) {
	$l = 0x82;
    } elsif ($len <= 0xffffff) {
	$l = 0x83;
    } else {
	$l = 0x84;
    }

    # autogenerate tag, if it is not passed
    if ($tag == -1) { $tag = int(rand(255)) & ~0x20; }

    # don't emit tag numbers >= 31 (X.690-0207 -- 8.1.2.4)
    if (($tag & 0x1f) == 0x1f) { $tag &= ~1; }

    $output .= pack("CC", $tag, $l);

    if ($len < 0x80) {
    } elsif ($len <= 0xff) {
	$output .= pack("C", $len);
    } elsif ($len <= 0xffff) {
	$output .= pack("n", $len);
    } elsif ($len <= 0xffffff) {
	$output .= pack("Cn", $len >> 16, $len & 0xffff);
    } else {
	$output .= pack("N", $len);
    }

    return $output;
}

###############################################################################
#
# Generate a random primitive
#
###############################################################################
sub emit_asn1_prim($)
{
    my ($tag) = @_;
    my $output;
    my $len = int(rand(255));

    $tag = int(rand(255)) & ~0x20
	if ($tag == -1);

    $output = emit_asn1_hdr($tag, $len);

    my $i = $len;
    while ($i > 16) {
	$output .= "abcdefghijklmnop";
	$i -= 16;
    }

    $output .= substr("abcdefghijklmnop", 0, $i);
    return $output;
}

###############################################################################
#
# Generate a random construct
#
###############################################################################
sub emit_asn1_cons($);
sub emit_asn1_cons($)
{
    my $output = "";
    my $count = int(rand(20));
    my ($tag) = @_;

    if ($depth >= $maxdepth) {
	return emit_asn1_prim($tag);
    }

    if ($tag == -1) {
	$tag = int(rand(255)) & ~0x20;
	if ($tag < 0x40 && $tag != 0x11) {
	    $tag = 0x10;
	}
	$tag |= 0x20;
    }

    $depth++;
    while ($count > 0) {
	if (int(rand(4 + $depth)) == 1) {
	    $output .= emit_asn1_cons(-1);
	} else {
	    $output .= emit_asn1_prim(-1);
	}
	$count--;
    }
    $depth--;

    return emit_asn1_hdr($tag, length($output)) . $output;
}

print emit_asn1_cons(-1);
